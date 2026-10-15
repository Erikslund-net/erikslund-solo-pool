// Failover state-machine coverage for RpcClient::call() via a scripted call_one (no network).
// Invariants pinned:
//   * bitcoin_nodes[0] is primary; the rest are failover, tried in order.
//   * a connection failure advances to the next endpoint and STICKS there.
//   * RPC errors are final except -9/-10/-28, which mean the endpoint is temporarily unavailable.
//   * connection failures skip the node for 30 seconds across all RPC paths.
//   * cooled nodes remain a fallback when every eligible node fails.
#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include <glaze/glaze.hpp>

#include "bitcoin/rpc_client.hpp"
#include "bitcoin/rpc_endpoint.hpp"
#include "core/errors.hpp"

using namespace erikslund;
using namespace erikslund::bitcoin;

namespace {

const std::string kTip(64, 'a');

std::string gbt_body(std::string_view previous_block_hash) {
    return std::string(R"({"result":{"height":170,"version":536870912,"curtime":1700000000,)") +
           R"("bits":"1d00ffff","coinbasevalue":5000000000,"previousblockhash":")" +
           std::string(previous_block_hash) + R"(","transactions":[]},"error":null,"id":1})";
}

class TimedRpc : public RpcClient {
public:
    using RpcClient::RpcClient;

    void advance_time(double seconds) {
        now_seconds_.fetch_add(seconds, std::memory_order_relaxed);
    }

protected:
    double steady_now_seconds() const override {
        return now_seconds_.load(std::memory_order_relaxed);
    }

private:
    std::atomic<double> now_seconds_{0.0};
};

// Drives call() without a network: each endpoint URL maps to a behaviour, and
// every attempt is counted so tests can assert exactly which nodes were tried.
class ScriptedRpc : public TimedRpc {
public:
    enum class Mode { Ok, Down, Timeout, WorkUnavailable, RpcErr };
    explicit ScriptedRpc(const std::vector<RpcEndpoint>& endpoints)
        : TimedRpc(endpoints, /*timeout_seconds=*/1) {}

    std::map<std::string, Mode> mode; // url -> behaviour
    std::map<std::string, int> hits;  // url -> times call_one ran
    glz::generic ok_result;           // when non-null, Mode::Ok returns this (e.g. a tip hash)
    std::map<std::string, Mode> gbt_modes;
    std::map<std::string, std::string> gbt_tips;

protected:
    glz::generic call_one(const Resolved& endpoint, const std::string& /*payload*/,
                          long /*timeout*/) override {
        ++hits[endpoint.url];
        switch (mode.at(endpoint.url)) {
        case Mode::Down:
            throw RpcConnectError("down: " + endpoint.url);
        case Mode::Timeout:
            throw RpcConnectionError("read timed out: " + endpoint.url);
        case Mode::WorkUnavailable:
            throw RpcError("Bitcoin Core is not connected", -9);
        case Mode::RpcErr:
            throw RpcError("node rejected the call", -22);
        case Mode::Ok:
            break;
        }
        if (!ok_result.is_null())
            return ok_result;
        glz::generic served;
        served["served_by"] = endpoint.url;
        return served;
    }

    std::string post_one(const Resolved& endpoint, const std::string&, long,
                         long*) override {
        ++hits[endpoint.url];
        const auto behavior = gbt_modes.find(endpoint.url);
        switch (behavior == gbt_modes.end() ? mode.at(endpoint.url) : behavior->second) {
        case Mode::Down:
            throw RpcConnectError("down: " + endpoint.url);
        case Mode::Timeout:
            throw RpcConnectionError("read timed out: " + endpoint.url);
        case Mode::WorkUnavailable:
            return R"({"result":null,"error":{"code":-9,"message":"Bitcoin Core is not connected!"},"id":1})";
        case Mode::RpcErr:
            return R"({"result":null,"error":{"code":-22,"message":"invalid request"},"id":1})";
        case Mode::Ok:
            const auto tip = gbt_tips.find(endpoint.url);
            return gbt_body(tip == gbt_tips.end() ? kTip : tip->second);
        }
        return {};
    }
};

class BlockingFailbackRpc final : public TimedRpc {
public:
    explicit BlockingFailbackRpc(const std::vector<RpcEndpoint>& endpoints)
        : TimedRpc(endpoints, 1), release_signal_(release_primary.get_future().share()) {}

    std::atomic<bool> primary_available{false};
    std::atomic<int> backup_template_requests{0};
    std::promise<void> primary_called;
    std::promise<void> release_primary;

protected:
    glz::generic call_one(const Resolved& endpoint, const std::string&, long) override {
        if (endpoint.url == "http://primary" && !primary_available.load())
            throw RpcConnectError("primary unavailable");
        return glz::generic(kTip);
    }

    std::string post_one(const Resolved& endpoint, const std::string&, long,
                         long*) override {
        if (endpoint.url == "http://primary") {
            primary_called.set_value();
            release_signal_.wait();
        } else {
            ++backup_template_requests;
        }
        return gbt_body(kTip);
    }

private:
    std::shared_future<void> release_signal_;
};

const std::vector<RpcEndpoint> kEndpoints = {
    {"http://primary", "u", "p"},
    {"http://backup1", "u", "p"},
    {"http://backup2", "u", "p"},
};

} // namespace

TEST_CASE("healthy primary serves every call; failover nodes are never touched") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Ok},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() =="http://primary");
    CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() =="http://primary");
    CHECK(rpc.hits["http://primary"] == 2);
    CHECK(rpc.hits.count("http://backup1") == 0);
}

TEST_CASE("a down primary fails over to the first reachable backup, and stops there") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() =="http://backup1");
    CHECK(rpc.hits["http://primary"] == 1);
    CHECK(rpc.hits["http://backup1"] == 1);
    CHECK(rpc.hits.count("http://backup2") == 0); // stopped at the first reachable
}

TEST_CASE("two down nodes are skipped to reach the third in one call") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Down},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() =="http://backup2");
    CHECK(rpc.hits["http://primary"] == 1);
    CHECK(rpc.hits["http://backup1"] == 1);
    CHECK(rpc.hits["http://backup2"] == 1);
}

TEST_CASE("an RPC error (node answered) is final -- it does NOT fail over") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::RpcErr},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    CHECK_THROWS_AS(rpc.call("submitblock"), RpcError);
    CHECK(rpc.hits["http://primary"] == 1);
    CHECK(rpc.hits.count("http://backup1") == 0); // a live node's answer is authoritative
}

TEST_CASE("a work-unavailable RPC error fails over during startup calls") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::WorkUnavailable},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    CHECK(rpc.call("getblockchaininfo")["served_by"].get<std::string>() == "http://backup1");
    CHECK(rpc.active_index() == 1);
    CHECK(rpc.hits["http://primary"] == 1);
    CHECK(rpc.hits["http://backup1"] == 1);
}

TEST_CASE("all endpoints down raises RpcConnectionError after trying each exactly once") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Down},
                {"http://backup2", ScriptedRpc::Mode::Down}};
    CHECK_THROWS_AS(rpc.call("getblockcount"), RpcConnectionError);
    CHECK(rpc.hits["http://primary"] == 1);
    CHECK(rpc.hits["http://backup1"] == 1);
    CHECK(rpc.hits["http://backup2"] == 1);
}

TEST_CASE("all cooled endpoints are retried immediately for mining work") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Down},
                {"http://backup2", ScriptedRpc::Mode::Down}};
    CHECK_THROWS_AS(rpc.call("getblockcount"), RpcConnectionError);
    SUBCASE("normal calls retry the recovered primary") {
        rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
        CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() == "http://primary");
        CHECK(rpc.hits["http://primary"] == 2);
    }
    SUBCASE("parsed GBT retries the recovered primary") {
        rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
        CHECK(rpc.getblocktemplate_parsed().height == 170);
        CHECK(rpc.hits["http://primary"] == 2);
    }
    SUBCASE("direct mining tip probes retry their active endpoint") {
        rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
        rpc.ok_result["chain"] = "regtest";
        rpc.ok_result["blocks"] = 170.0;
        rpc.ok_result["bestblockhash"] = kTip;
        CHECK(rpc.get_mining_tip().hash == kTip);
        CHECK(rpc.hits["http://primary"] == 2);
    }
    SUBCASE("one failed retry cannot sideline later cooled nodes") {
        CHECK_THROWS_AS(rpc.call("getblockcount"), RpcConnectionError);
        for (const auto& [url, hits] : rpc.hits)
            CHECK(hits == 2);
    }
}

TEST_CASE("normal calls rescue a cooled primary after every eligible backup fails") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    rpc.call("getblockcount");
    rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
    rpc.mode["http://backup1"] = ScriptedRpc::Mode::Timeout;
    rpc.mode["http://backup2"] = ScriptedRpc::Mode::Down;
    SUBCASE("a failure to connect to the last live backup also rescues the primary") {
        rpc.mode["http://backup1"] = ScriptedRpc::Mode::Down;
    }
    CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() == "http://primary");
    CHECK(rpc.active_index() == 0);
    CHECK(rpc.hits["http://primary"] == 2);
    CHECK(rpc.hits["http://backup1"] == 2);
    CHECK(rpc.hits["http://backup2"] == 1);

    rpc.mode["http://backup1"] = ScriptedRpc::Mode::Ok;
    CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() == "http://primary");
    CHECK(rpc.hits["http://primary"] == 3);
    CHECK(rpc.hits["http://backup1"] == 2);
}

TEST_CASE("failback respects connection cooldown without consuming its probe interval") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    rpc.call("getblockcount");
    rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
    rpc.ok_result = kTip;

    rpc.maybe_failback(kTip);
    rpc.advance_time(RpcClient::kConnectionCooldownSeconds - 1.0);
    rpc.maybe_failback(kTip);
    CHECK(rpc.hits["http://primary"] == 1);
    rpc.advance_time(1.0);
    rpc.maybe_failback(kTip);
    CHECK(rpc.getblocktemplate_parsed().previousblockhash == kTip);
    CHECK(rpc.active_index() == 0);
    CHECK(rpc.hits["http://primary"] == 3);
}

TEST_CASE("failback discards a cached template when the primary becomes unreachable again") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    rpc.call("getblockcount");
    REQUIRE(rpc.hits["http://primary"] == 1);
    rpc.advance_time(RpcClient::kConnectionCooldownSeconds);
    rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
    rpc.ok_result = kTip;
    rpc.maybe_failback(kTip);
    REQUIRE(rpc.active_index() == 1);
    REQUIRE(rpc.hits["http://primary"] == 3);

    rpc.advance_time(RpcClient::kFailbackProbeSeconds);
    rpc.mode["http://primary"] = ScriptedRpc::Mode::Down;
    rpc.maybe_failback(kTip);
    CHECK(rpc.hits["http://primary"] == 4);
    CHECK(rpc.getblocktemplate_parsed().previousblockhash == kTip);
    CHECK(rpc.active_index() == 1);
    CHECK(rpc.hits["http://primary"] == 4);
    CHECK(rpc.hits["http://backup1"] == 2);
}

TEST_CASE("failover is sticky: a recovered primary is not retried while the backup is healthy") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() =="http://backup1"); // moves to backup1
    rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;                // primary comes back
    CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() =="http://backup1");
    CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() =="http://backup1");
    CHECK(rpc.hits["http://primary"] == 1);  // contacted once (the initial failure), never again
    CHECK(rpc.hits["http://backup1"] == 3);
}

TEST_CASE("endpoint_urls lists nodes in order; active_index tracks the current endpoint") {
    ScriptedRpc rpc(kEndpoints);
    const auto urls = rpc.endpoint_urls();
    REQUIRE(urls.size() == 3);
    CHECK(urls[0] == "http://primary");
    CHECK(urls[1] == "http://backup1");
    CHECK(urls[2] == "http://backup2");
    CHECK(rpc.active_index() == 0); // starts on the primary

    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    rpc.call("getblockcount");
    CHECK(rpc.active_index() == 1); // advanced + stuck on backup1
}

TEST_CASE("maybe_failback prepares a primary GBT only after its tip catches up") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() =="http://backup1"); // fail over
    REQUIRE(rpc.active_index() == 1);
    rpc.advance_time(RpcClient::kConnectionCooldownSeconds);

    SUBCASE("primary still down -> probe fails, stays on the backup") {
        rpc.maybe_failback(kTip); // first probe is immediate (no prior probe recorded)
        CHECK(rpc.active_index() == 1);
        CHECK(rpc.hits["http://primary"] == 2); // the initial failure + the probe
        // A second probe inside the kFailbackProbeSeconds window is rate-limited away.
        rpc.maybe_failback(kTip);
        CHECK(rpc.hits["http://primary"] == 2);
    }
    SUBCASE("a matching tip and valid template fail back on the next GBT") {
        rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
        rpc.ok_result = kTip;
        rpc.maybe_failback(kTip);
        CHECK(rpc.active_index() == 1);
        const int primary_requests = rpc.hits["http://primary"];
        CHECK(rpc.getblocktemplate_parsed().previousblockhash == kTip);
        CHECK(rpc.hits["http://primary"] == primary_requests);
        CHECK(rpc.active_index() == 0);
        rpc.ok_result = glz::generic{};
        CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() =="http://primary");
    }
    SUBCASE("an RPC error during the cheap probe does not schedule failback") {
        rpc.mode["http://primary"] = ScriptedRpc::Mode::RpcErr;
        rpc.maybe_failback(kTip);
        CHECK(rpc.active_index() == 1);
    }
    SUBCASE("a different tip does not schedule failback") {
        rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
        rpc.ok_result = std::string(64, 'b');
        rpc.maybe_failback(kTip);
        CHECK(rpc.active_index() == 1);
    }
    SUBCASE("a candidate GBT error keeps serving from the active backup") {
        rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
        rpc.ok_result = kTip;
        rpc.gbt_modes["http://primary"] = ScriptedRpc::Mode::RpcErr;
        rpc.maybe_failback(kTip);
        CHECK(rpc.getblocktemplate_parsed().previousblockhash == kTip);
        CHECK(rpc.active_index() == 1);
    }
    SUBCASE("a candidate unavailable response keeps serving from the active backup") {
        rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
        rpc.ok_result = kTip;
        rpc.gbt_modes["http://primary"] = ScriptedRpc::Mode::WorkUnavailable;
        rpc.maybe_failback(kTip);
        CHECK(rpc.getblocktemplate_parsed().previousblockhash == kTip);
        CHECK(rpc.active_index() == 1);
    }
    SUBCASE("a candidate template for a different tip keeps the active backup") {
        rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
        rpc.ok_result = kTip;
        rpc.gbt_tips["http://primary"] = std::string(64, 'b');
        rpc.maybe_failback(kTip);
        CHECK(rpc.getblocktemplate_parsed().previousblockhash == kTip);
        CHECK(rpc.active_index() == 1);
    }
    SUBCASE("a cached candidate is discarded when the active tip advances") {
        rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
        rpc.ok_result = kTip;
        rpc.maybe_failback(kTip);
        const std::string new_tip(64, 'b');
        rpc.ok_result = new_tip;
        rpc.gbt_tips["http://backup1"] = new_tip;
        CHECK(rpc.getblocktemplate_parsed().previousblockhash == new_tip);
        CHECK(rpc.active_index() == 1);
    }
}

TEST_CASE("a blocked failback GBT does not delay templates from the active backup") {
    using namespace std::chrono_literals;

    BlockingFailbackRpc rpc(kEndpoints);
    rpc.call("getblockcount");
    REQUIRE(rpc.active_index() == 1);
    rpc.primary_available = true;
    rpc.advance_time(RpcClient::kConnectionCooldownSeconds);
    auto primary_called = rpc.primary_called.get_future();
    auto recovery = std::async(std::launch::async, [&rpc] { rpc.maybe_failback(kTip); });
    const auto primary_status = primary_called.wait_for(1s);
    auto work = std::async(std::launch::async, [&rpc] { return rpc.getblocktemplate_parsed(); });
    const auto work_status = work.wait_for(1s);
    rpc.release_primary.set_value();
    recovery.get();
    const auto block_template = work.get();

    CHECK(primary_status == std::future_status::ready);
    CHECK(work_status == std::future_status::ready);
    CHECK(block_template.previousblockhash == kTip);
    CHECK(rpc.backup_template_requests.load() == 1);
    CHECK(rpc.active_index() == 1);
    CHECK(rpc.getblocktemplate_parsed().previousblockhash == kTip);
    CHECK(rpc.active_index() == 0);
}

TEST_CASE("maybe_failback is a no-op while already on the primary or with no tip yet") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    rpc.maybe_failback(std::string(64, 'a')); // on the primary: no probe
    CHECK(rpc.hits.count("http://primary") == 0);
    CHECK(rpc.active_index() == 0);

    rpc.call("getblockcount"); // fail over to backup1
    REQUIRE(rpc.active_index() == 1);
    rpc.maybe_failback(""); // no tip to compare against yet: no probe
    CHECK(rpc.hits["http://primary"] == 1); // only the original failed call
}

TEST_CASE("from a backup, a fresh failure rotates and wraps to a recovered primary") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Down}};
    CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() =="http://backup1"); // current -> backup1
    // backup1 dies, primary recovered: backup1 -> backup2(down) -> wrap -> primary.
    rpc.mode["http://backup1"] = ScriptedRpc::Mode::Down;
    rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
    rpc.advance_time(RpcClient::kConnectionCooldownSeconds);
    CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() =="http://primary");
    CHECK(rpc.hits["http://backup2"] == 1); // tried once on the wrap-around
}

namespace {

class SubmitRpc : public TimedRpc {
public:
    enum class Reply {
        Accepted,
        Duplicate,
        Inconclusive,
        Rejected,
        BadPreviousBlock,
        Down,
        Timeout,
        RpcError
    };

    explicit SubmitRpc(const std::vector<RpcEndpoint>& endpoints)
        : TimedRpc(endpoints, /*timeout_seconds=*/1) {}

    std::map<std::string, Reply> replies;

    int hit_count(const std::string& url) {
        const std::scoped_lock lock(mutex_);
        return hits_[url];
    }

    void reset_hits() {
        const std::scoped_lock lock(mutex_);
        hits_.clear();
    }

protected:
    glz::generic call_one(const Resolved& endpoint, const std::string&, long) override {
        Reply reply;
        {
            const std::scoped_lock lock(mutex_);
            ++hits_[endpoint.url];
            reply = replies.at(endpoint.url);
        }
        switch (reply) {
        case Reply::Accepted: return glz::generic{};
        case Reply::Duplicate: return glz::generic(std::string("duplicate"));
        case Reply::Inconclusive: return glz::generic(std::string("inconclusive"));
        case Reply::Rejected: return glz::generic(std::string("high-hash"));
        case Reply::BadPreviousBlock: return glz::generic(std::string("bad-prevblk"));
        case Reply::Down: throw RpcConnectError("down: " + endpoint.url);
        case Reply::Timeout: throw RpcConnectionError("read timed out: " + endpoint.url);
        case Reply::RpcError: throw erikslund::RpcError("submitblock denied", -22);
        }
        throw std::logic_error("unhandled submitblock reply");
    }

private:
    std::mutex mutex_;
    std::map<std::string, int> hits_;
};

class BlockingSubmitRpc : public TimedRpc {
public:
    explicit BlockingSubmitRpc(const std::vector<RpcEndpoint>& endpoints)
        : TimedRpc(endpoints, /*timeout_seconds=*/1),
          release_signal_(release_primary.get_future().share()) {}

    std::promise<void> primary_called;
    std::promise<void> backup_called;
    std::promise<void> release_primary;

protected:
    glz::generic call_one(const Resolved& endpoint, const std::string& payload, long) override {
        const bool is_submission = payload.find("\"method\":\"submitblock\"") != std::string::npos;
        if (endpoint.url == "http://primary") {
            if (!is_submission)
                throw RpcConnectError("primary unavailable");
            primary_called.set_value();
            release_signal_.wait();
            throw RpcConnectionError("primary timed out");
        }
        if (endpoint.url == "http://backup1") {
            if (is_submission)
                backup_called.set_value();
            return glz::generic{};
        }
        return glz::generic(std::string("high-hash"));
    }

private:
    std::shared_future<void> release_signal_;
};

class ConcurrentRecoveryRpc final : public TimedRpc {
public:
    explicit ConcurrentRecoveryRpc(const std::vector<RpcEndpoint>& endpoints)
        : TimedRpc(endpoints, 1), release_signal_(release_old_success.get_future().share()) {}

    std::promise<void> old_request_entered;
    std::promise<void> release_old_success;
    std::atomic<int> primary_requests{0};

protected:
    glz::generic call_one(const Resolved& endpoint, const std::string& payload, long) override {
        if (endpoint.url == "http://primary") {
            primary_requests.fetch_add(1, std::memory_order_relaxed);
            if (payload.find("slow_success") != std::string::npos) {
                old_request_entered.set_value();
                release_signal_.wait();
            } else if (payload.find("getblockchaininfo") != std::string::npos) {
                throw RpcConnectError("new connection attempt failed");
            }
        }
        return glz::generic{};
    }

private:
    std::shared_future<void> release_signal_;
};

} // namespace

TEST_CASE("submitblock sends the block to every endpoint and any acceptance wins") {
    SubmitRpc rpc(kEndpoints);
    rpc.replies = {{"http://primary", SubmitRpc::Reply::Rejected},
                   {"http://backup1", SubmitRpc::Reply::Accepted},
                   {"http://backup2", SubmitRpc::Reply::Down}};

    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK(rpc.hit_count("http://primary") == 1);
    CHECK(rpc.hit_count("http://backup1") == 1);
    CHECK(rpc.hit_count("http://backup2") == 1);
    CHECK(rpc.active_index() == 0);
}

TEST_CASE("submitblock treats a valid duplicate from any endpoint as success") {
    SubmitRpc rpc(kEndpoints);
    rpc.replies = {{"http://primary", SubmitRpc::Reply::RpcError},
                   {"http://backup1", SubmitRpc::Reply::Rejected},
                   {"http://backup2", SubmitRpc::Reply::Duplicate}};

    CHECK(rpc.submitblock("00") == "duplicate");
    CHECK(rpc.hit_count("http://primary") == 1);
    CHECK(rpc.hit_count("http://backup1") == 1);
    CHECK(rpc.hit_count("http://backup2") == 1);
}

TEST_CASE("submitblock does not change the active work endpoint") {
    SubmitRpc rpc(kEndpoints);
    rpc.replies = {{"http://primary", SubmitRpc::Reply::Down},
                   {"http://backup1", SubmitRpc::Reply::Rejected},
                   {"http://backup2", SubmitRpc::Reply::Rejected}};
    rpc.call("getblockcount");
    REQUIRE(rpc.active_index() == 1);
    rpc.advance_time(RpcClient::kConnectionCooldownSeconds);

    rpc.reset_hits();
    rpc.replies = {{"http://primary", SubmitRpc::Reply::Accepted},
                   {"http://backup1", SubmitRpc::Reply::Rejected},
                   {"http://backup2", SubmitRpc::Reply::Rejected}};
    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK(rpc.hit_count("http://primary") == 1);
    CHECK(rpc.hit_count("http://backup1") == 1);
    CHECK(rpc.hit_count("http://backup2") == 1);
    CHECK(rpc.active_index() == 1);
}

TEST_CASE("submitblock skips a connection failure learned by another RPC path") {
    SubmitRpc rpc(kEndpoints);
    rpc.replies = {{"http://primary", SubmitRpc::Reply::Down},
                   {"http://backup1", SubmitRpc::Reply::Accepted},
                   {"http://backup2", SubmitRpc::Reply::Rejected}};
    SUBCASE("normal calls share connection failures with submission") {
        rpc.call("getblockcount");
        CHECK(rpc.active_index() == 1);
    }
    SUBCASE("direct mining tip probes share connection failures with submission") {
        CHECK_THROWS_AS(rpc.get_mining_tip(), RpcConnectionError);
        CHECK(rpc.active_index() == 0);
    }
    const size_t work_endpoint = rpc.active_index();
    rpc.reset_hits();
    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK(rpc.hit_count("http://primary") == 0);
    CHECK(rpc.hit_count("http://backup1") == 1);
    CHECK(rpc.hit_count("http://backup2") == 1);
    CHECK(rpc.active_index() == work_endpoint);
}

TEST_CASE("submitblock cooldown expires and a repeated failure starts a new interval") {
    SubmitRpc rpc(kEndpoints);
    rpc.replies = {{"http://primary", SubmitRpc::Reply::Down},
                   {"http://backup1", SubmitRpc::Reply::Accepted},
                   {"http://backup2", SubmitRpc::Reply::Rejected}};
    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK(rpc.hit_count("http://primary") == 1);
    rpc.advance_time(RpcClient::kConnectionCooldownSeconds - 1.0);
    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK(rpc.hit_count("http://primary") == 1);
    rpc.advance_time(1.0);
    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK(rpc.hit_count("http://primary") == 2);

    rpc.replies["http://primary"] = SubmitRpc::Reply::Accepted;
    rpc.advance_time(RpcClient::kConnectionCooldownSeconds - 1.0);
    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK(rpc.hit_count("http://primary") == 2);
    rpc.advance_time(1.0);
    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK(rpc.hit_count("http://primary") == 3);
    CHECK(rpc.active_index() == 0);
}

TEST_CASE("submission stays retryable when a cooled endpoint has not rejected the block") {
    SubmitRpc rpc(kEndpoints);
    rpc.replies = {{"http://primary", SubmitRpc::Reply::Down},
                   {"http://backup1", SubmitRpc::Reply::Rejected},
                   {"http://backup2", SubmitRpc::Reply::Rejected}};
    CHECK_THROWS_AS(rpc.submitblock("00"), RpcConnectionError);
    CHECK_THROWS_AS(rpc.submitblock("00"), RpcConnectionError);
    CHECK(rpc.hit_count("http://primary") == 1);
    CHECK(rpc.hit_count("http://backup1") == 2);
    CHECK(rpc.hit_count("http://backup2") == 2);

    SUBCASE("a valid duplicate still wins over a skipped endpoint") {
        rpc.replies["http://backup1"] = SubmitRpc::Reply::Duplicate;
        CHECK(rpc.submitblock("00") == "duplicate");
    }
    SUBCASE("inconclusive remains retryable with a skipped endpoint") {
        rpc.replies["http://backup1"] = SubmitRpc::Reply::Inconclusive;
        CHECK(rpc.submitblock("00") == "inconclusive");
    }
    SUBCASE("the recovered node can accept after cooldown") {
        rpc.replies["http://primary"] = SubmitRpc::Reply::Accepted;
        rpc.advance_time(RpcClient::kConnectionCooldownSeconds);
        CHECK_FALSE(rpc.submitblock("00").has_value());
        CHECK(rpc.hit_count("http://primary") == 2);
    }
}

TEST_CASE("all cooled submitblock endpoints are retried and keep the block retryable") {
    SubmitRpc rpc(kEndpoints);
    rpc.replies = {{"http://primary", SubmitRpc::Reply::Down},
                   {"http://backup1", SubmitRpc::Reply::Down},
                   {"http://backup2", SubmitRpc::Reply::Down}};
    CHECK_THROWS_AS(rpc.submitblock("00"), RpcConnectionError);
    CHECK_THROWS_AS(rpc.submitblock("00"), RpcConnectionError);
    CHECK_THROWS_AS(rpc.call("getblockcount"), RpcConnectionError);
    for (const auto& endpoint : kEndpoints)
        CHECK(rpc.hit_count(endpoint.url) == 3);
}

TEST_CASE("submitblock can recover immediately when every endpoint is cooled") {
    SubmitRpc rpc(kEndpoints);
    rpc.replies = {{"http://primary", SubmitRpc::Reply::Down},
                   {"http://backup1", SubmitRpc::Reply::Down},
                   {"http://backup2", SubmitRpc::Reply::Down}};
    CHECK_THROWS_AS(rpc.submitblock("00"), RpcConnectionError);
    rpc.replies["http://primary"] = SubmitRpc::Reply::Accepted;
    CHECK_FALSE(rpc.submitblock("00").has_value());
    for (const auto& endpoint : kEndpoints)
        CHECK(rpc.hit_count(endpoint.url) == 2);
    CHECK(rpc.active_index() == 0);
}

TEST_CASE("submitblock rescues cooled endpoints without discarding an earlier unresolved response") {
    SubmitRpc rpc(kEndpoints);
    rpc.replies = {{"http://primary", SubmitRpc::Reply::Down},
                   {"http://backup1", SubmitRpc::Reply::Rejected},
                   {"http://backup2", SubmitRpc::Reply::Rejected}};
    rpc.call("getblockcount");
    rpc.replies["http://primary"] = SubmitRpc::Reply::Accepted;
    rpc.replies["http://backup1"] = SubmitRpc::Reply::Timeout;
    rpc.replies["http://backup2"] = SubmitRpc::Reply::Down;
    SUBCASE("a recovered primary accepts after the backups fail") {
        CHECK_FALSE(rpc.submitblock("00").has_value());
        rpc.replies["http://backup1"] = SubmitRpc::Reply::Rejected;
        CHECK_FALSE(rpc.submitblock("00").has_value());
        CHECK(rpc.hit_count("http://primary") == 3);
        CHECK(rpc.hit_count("http://backup2") == 1);
    }
    SUBCASE("a recovered primary rejection cannot make an earlier timeout final") {
        rpc.replies["http://primary"] = SubmitRpc::Reply::Rejected;
        CHECK_THROWS_AS(rpc.submitblock("00"), RpcConnectionError);
        CHECK(rpc.hit_count("http://primary") == 2);
    }
    CHECK(rpc.active_index() == 1);
}

TEST_CASE("JSON-RPC submission errors do not trigger a connection cooldown") {
    SubmitRpc rpc(kEndpoints);
    rpc.replies = {{"http://primary", SubmitRpc::Reply::RpcError},
                   {"http://backup1", SubmitRpc::Reply::Accepted},
                   {"http://backup2", SubmitRpc::Reply::Rejected}};
    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK(rpc.hit_count("http://primary") == 2);
}

TEST_CASE("submitblock retries unless every endpoint definitively rejects") {
    SubmitRpc rpc(kEndpoints);

    SUBCASE("an inconclusive response keeps the block pending") {
        rpc.replies = {{"http://primary", SubmitRpc::Reply::Rejected},
                       {"http://backup1", SubmitRpc::Reply::Inconclusive},
                       {"http://backup2", SubmitRpc::Reply::Down}};
        CHECK(rpc.submitblock("00") == "inconclusive");
    }
    SUBCASE("a connection error keeps the block pending") {
        rpc.replies = {{"http://primary", SubmitRpc::Reply::Rejected},
                       {"http://backup1", SubmitRpc::Reply::Down},
                       {"http://backup2", SubmitRpc::Reply::Rejected}};
        CHECK_THROWS_AS(rpc.submitblock("00"), RpcConnectionError);
    }
    SUBCASE("an RPC error keeps the block pending") {
        rpc.replies = {{"http://primary", SubmitRpc::Reply::Rejected},
                       {"http://backup1", SubmitRpc::Reply::RpcError},
                       {"http://backup2", SubmitRpc::Reply::Rejected}};
        CHECK_THROWS_AS(rpc.submitblock("00"), RpcError);
    }
    SUBCASE("all definitive rejections are final") {
        rpc.replies = {{"http://primary", SubmitRpc::Reply::Rejected},
                       {"http://backup1", SubmitRpc::Reply::BadPreviousBlock},
                       {"http://backup2", SubmitRpc::Reply::BadPreviousBlock}};
        CHECK(rpc.submitblock("00") == "high-hash");
    }
    CHECK(rpc.hit_count("http://primary") == 1);
    CHECK(rpc.hit_count("http://backup1") == 1);
    CHECK(rpc.hit_count("http://backup2") == 1);
}

TEST_CASE("a blocked submitblock endpoint does not delay another endpoint") {
    using namespace std::chrono_literals;

    BlockingSubmitRpc rpc(kEndpoints);
    auto primary_called = rpc.primary_called.get_future();
    auto backup_called = rpc.backup_called.get_future();
    auto submission = std::async(std::launch::async, [&rpc] { return rpc.submitblock("00"); });

    const auto primary_status = primary_called.wait_for(1s);
    const auto backup_status = backup_called.wait_for(1s);
    rpc.release_primary.set_value();
    const auto result = submission.get();

    CHECK(primary_status == std::future_status::ready);
    CHECK(backup_status == std::future_status::ready);
    CHECK_FALSE(result.has_value());
}

TEST_CASE("a known dead node does not delay submitblock completion") {
    using namespace std::chrono_literals;

    BlockingSubmitRpc rpc(kEndpoints);
    rpc.call("getblockcount");
    REQUIRE(rpc.active_index() == 1);
    auto primary_called = rpc.primary_called.get_future();
    auto submission = std::async(std::launch::async, [&rpc] { return rpc.submitblock("00"); });
    const auto submission_status = submission.wait_for(1s);
    const auto primary_status = primary_called.wait_for(0s);
    rpc.release_primary.set_value();
    const auto result = submission.get();

    CHECK(submission_status == std::future_status::ready);
    CHECK(primary_status == std::future_status::timeout);
    CHECK_FALSE(result.has_value());
    CHECK(rpc.active_index() == 1);
}

TEST_CASE("an older concurrent success cannot clear a newer connection failure") {
    using namespace std::chrono_literals;

    ConcurrentRecoveryRpc rpc(kEndpoints);
    auto entered = rpc.old_request_entered.get_future();
    auto old_success = std::async(std::launch::async, [&rpc] { return rpc.call("slow_success"); });
    const auto entered_status = entered.wait_for(1s);
    CHECK_THROWS_AS(rpc.get_mining_tip(), RpcConnectionError);
    rpc.release_old_success.set_value();
    old_success.get();

    CHECK(entered_status == std::future_status::ready);
    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK(rpc.primary_requests.load(std::memory_order_relaxed) == 2);
    CHECK(rpc.active_index() == 0);
}

// The raw GBT path parses directly into a BlockTemplate before publishing a new active endpoint.
namespace {

class ScriptedRawRpc : public TimedRpc {
public:
    enum class Mode { Ok, Down, Timeout, NotConnected, InitialDownload, Warmup,
                      RpcErr, Garbage, MissingResult };
    explicit ScriptedRawRpc(const std::vector<RpcEndpoint>& endpoints)
        : TimedRpc(endpoints, /*timeout_seconds=*/1) {}

    std::map<std::string, Mode> mode;
    std::map<std::string, int> hits;
    long response_status = 200;

protected:
    std::string post_one(const Resolved& endpoint, const std::string& payload, long /*timeout*/,
                         long* http_status) override {
        {
            const std::scoped_lock lock(mutex_);
            ++hits[endpoint.url];
        }
        if (http_status)
            *http_status = response_status;
        switch (mode.at(endpoint.url)) {
        case Mode::Down:
            throw RpcConnectError("down: " + endpoint.url);
        case Mode::Timeout:
            throw RpcConnectionError("read timed out: " + endpoint.url);
        case Mode::NotConnected:
            return R"({"result":null,"error":{"code":-9,"message":"Bitcoin Core is not connected!"},"id":1})";
        case Mode::InitialDownload:
            return R"({"result":null,"error":{"code":-10,"message":"initial download"},"id":1})";
        case Mode::Warmup:
            return R"({"result":null,"error":{"code":-28,"message":"warming up"},"id":1})";
        case Mode::RpcErr:
            return R"({"result":null,"error":{"code":-22,"message":"invalid request"},"id":1})";
        case Mode::Garbage:
            return "not json at all";
        case Mode::MissingResult:
            return R"({"error":null,"id":1})";
        case Mode::Ok:
            break;
        }
        if (payload.find("submitblock") != std::string::npos)
            return R"({"result":null,"error":null,"id":1})";
        if (payload.find("getblockchaininfo") != std::string::npos)
            return R"({"result":{"chain":"regtest","blocks":170,"bestblockhash":")" +
                   kTip + R"("},"error":null,"id":1})";
        return gbt_body(kTip);
    }

private:
    std::mutex mutex_;
};

} // namespace

TEST_CASE("getblocktemplate_parsed fails over a down primary and parses from the backup") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Down},
                {"http://backup1", ScriptedRawRpc::Mode::Ok},
                {"http://backup2", ScriptedRawRpc::Mode::Ok}};
    const auto tmpl = rpc.getblocktemplate_parsed();
    CHECK(tmpl.height == 170);
    CHECK(tmpl.bits == 0x1d00ffffu);
    CHECK(tmpl.previousblockhash == std::string(64, 'a'));
    CHECK(rpc.active_index() == 1); // stuck on the backup, like call()
}

TEST_CASE("raw GBT connection failures share cooldown when another endpoint is available") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Down},
                {"http://backup1", ScriptedRawRpc::Mode::Ok},
                {"http://backup2", ScriptedRawRpc::Mode::Ok}};
    CHECK(rpc.getblocktemplate_parsed().height == 170);
    rpc.mode["http://primary"] = ScriptedRawRpc::Mode::Ok;
    CHECK(rpc.getblocktemplate_parsed().height == 170);
    CHECK(rpc.call("getblockcount")["height"].get<double>() == 170);
    CHECK(rpc.get_mining_tip().hash == kTip);
    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK(rpc.hits["http://primary"] == 1);
    rpc.advance_time(RpcClient::kConnectionCooldownSeconds);
    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK(rpc.hits["http://primary"] == 2);
}

TEST_CASE("single-node RPC operations retry immediately after a connection failure") {
    ScriptedRawRpc rpc({kEndpoints.front()});
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Down}};
    SUBCASE("normal calls") {
        CHECK_THROWS_AS(rpc.call("getblockcount"), RpcConnectionError);
        rpc.mode["http://primary"] = ScriptedRawRpc::Mode::Ok;
        CHECK(rpc.call("getblockcount")["height"].get<double>() == 170);
    }
    SUBCASE("parsed GBT") {
        CHECK_THROWS_AS(rpc.getblocktemplate_parsed(), RpcConnectionError);
        rpc.mode["http://primary"] = ScriptedRawRpc::Mode::Ok;
        CHECK(rpc.getblocktemplate_parsed().height == 170);
    }
    SUBCASE("mining tip readiness") {
        CHECK_THROWS_AS(rpc.get_mining_tip(), RpcConnectionError);
        rpc.mode["http://primary"] = ScriptedRawRpc::Mode::Ok;
        CHECK(rpc.get_mining_tip().hash == kTip);
    }
    SUBCASE("block submission") {
        CHECK_THROWS_AS(rpc.submitblock("00"), RpcConnectionError);
        rpc.mode["http://primary"] = ScriptedRawRpc::Mode::Ok;
        CHECK_FALSE(rpc.submitblock("00").has_value());
    }
    CHECK(rpc.hits["http://primary"] == 2);
}

TEST_CASE("read timeouts do not cool RPC endpoints across work and submission paths") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Timeout},
                {"http://backup1", ScriptedRawRpc::Mode::Ok},
                {"http://backup2", ScriptedRawRpc::Mode::Ok}};
    SUBCASE("normal calls") { rpc.call("getblockcount"); }
    SUBCASE("parsed GBT") { rpc.getblocktemplate_parsed(); }
    SUBCASE("mining tip readiness") {
        CHECK_THROWS_AS(rpc.get_mining_tip(), RpcConnectionError);
    }
    SUBCASE("block submission") { CHECK_FALSE(rpc.submitblock("00").has_value()); }
    REQUIRE(rpc.hits["http://primary"] == 1);
    rpc.mode["http://primary"] = ScriptedRawRpc::Mode::Ok;
    CHECK_FALSE(rpc.submitblock("00").has_value());
    CHECK(rpc.hits["http://primary"] == 2);
}

TEST_CASE("all cooled raw GBT endpoints remain eligible after another connection failure") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Down},
                {"http://backup1", ScriptedRawRpc::Mode::Down},
                {"http://backup2", ScriptedRawRpc::Mode::Down}};
    CHECK_THROWS_AS(rpc.getblocktemplate_parsed(), RpcConnectionError);
    CHECK_THROWS_AS(rpc.getblocktemplate_parsed(), RpcConnectionError);
    for (const auto& endpoint : kEndpoints)
        CHECK(rpc.hits[endpoint.url] == 2);
}

TEST_CASE("parsed GBT rescues a cooled primary when eligible backups cannot provide work") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Down},
                {"http://backup1", ScriptedRawRpc::Mode::Ok},
                {"http://backup2", ScriptedRawRpc::Mode::Ok}};
    CHECK(rpc.getblocktemplate_parsed().height == 170);
    rpc.mode["http://primary"] = ScriptedRawRpc::Mode::Ok;
    rpc.mode["http://backup1"] = ScriptedRawRpc::Mode::Timeout;
    rpc.mode["http://backup2"] = ScriptedRawRpc::Mode::Down;
    SUBCASE("a not-ready backup also allows the cooled primary to recover") {
        rpc.mode["http://backup1"] = ScriptedRawRpc::Mode::Warmup;
    }
    CHECK(rpc.getblocktemplate_parsed().height == 170);
    CHECK(rpc.active_index() == 0);
    CHECK(rpc.hits["http://primary"] == 2);
    CHECK(rpc.hits["http://backup1"] == 2);
    CHECK(rpc.hits["http://backup2"] == 1);
    rpc.mode["http://backup1"] = ScriptedRawRpc::Mode::Ok;
    CHECK(rpc.getblocktemplate_parsed().height == 170);
    CHECK(rpc.hits["http://primary"] == 3);
    CHECK(rpc.hits["http://backup1"] == 2);
}

TEST_CASE("responding HTTP and JSON-RPC failures do not open the connection breaker") {
    ScriptedRawRpc rpc({kEndpoints.front()});
    SUBCASE("malformed JSON in the normal path") {
        rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Garbage}};
        CHECK_THROWS_AS(rpc.call("getblockcount"), RpcConnectionError);
    }
    SUBCASE("malformed GBT in the raw path") {
        rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Garbage}};
        CHECK_THROWS_AS(rpc.getblocktemplate_parsed(), RpcConnectionError);
    }
    SUBCASE("an HTTP authentication error with a non-JSON body") {
        rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Garbage}};
        rpc.response_status = 401;
        CHECK_THROWS_AS(rpc.call("getblockcount"), RpcConnectionError);
    }
    SUBCASE("a JSON reply without a result") {
        rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::MissingResult}};
        CHECK_THROWS_AS(rpc.call("getblockcount"), RpcConnectionError);
    }
    SUBCASE("a JSON-RPC request rejection") {
        rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::RpcErr}};
        CHECK_THROWS_AS(rpc.call("getblockcount"), RpcError);
    }
    SUBCASE("a temporary Core availability error") {
        rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Warmup}};
        CHECK_THROWS_AS(rpc.getblocktemplate_parsed(), RpcConnectionError);
    }
    rpc.mode["http://primary"] = ScriptedRawRpc::Mode::Ok;
    CHECK(rpc.getblocktemplate_parsed().height == 170);
    CHECK(rpc.hits["http://primary"] == 2);
}

TEST_CASE("getblocktemplate_parsed treats an unparseable body like a down endpoint") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Garbage},
                {"http://backup1", ScriptedRawRpc::Mode::Ok},
                {"http://backup2", ScriptedRawRpc::Mode::Ok}};
    CHECK(rpc.getblocktemplate_parsed().height == 170);
    CHECK(rpc.active_index() == 1);
}

TEST_CASE("getblocktemplate_parsed fails over when Core is not connected") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::NotConnected},
                {"http://backup1", ScriptedRawRpc::Mode::Ok},
                {"http://backup2", ScriptedRawRpc::Mode::Ok}};
    CHECK(rpc.getblocktemplate_parsed().height == 170);
    CHECK(rpc.active_index() == 1);
    CHECK(rpc.hits["http://primary"] == 1);
    CHECK(rpc.hits["http://backup1"] == 1);
}

TEST_CASE("getblocktemplate_parsed skips every temporary Core availability error") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::InitialDownload},
                {"http://backup1", ScriptedRawRpc::Mode::Warmup},
                {"http://backup2", ScriptedRawRpc::Mode::Ok}};
    CHECK(rpc.getblocktemplate_parsed().height == 170);
    CHECK(rpc.active_index() == 2);
}

TEST_CASE("getblocktemplate_parsed keeps arbitrary RPC errors terminal") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::RpcErr},
                {"http://backup1", ScriptedRawRpc::Mode::Ok},
                {"http://backup2", ScriptedRawRpc::Mode::Ok}};
    CHECK_THROWS_AS(rpc.getblocktemplate_parsed(), RpcError);
    CHECK(rpc.active_index() == 0);                 // no failover
    CHECK(rpc.hits.count("http://backup1") == 0);   // backups never touched
}

TEST_CASE("getblocktemplate_parsed skips but never sticks to an unavailable backup") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Down},
                {"http://backup1", ScriptedRawRpc::Mode::Warmup},
                {"http://backup2", ScriptedRawRpc::Mode::Ok}};
    CHECK(rpc.getblocktemplate_parsed().height == 170);
    CHECK(rpc.active_index() == 2);
}

TEST_CASE("getblocktemplate_parsed reports all unavailable endpoints as a connection error") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::NotConnected},
                {"http://backup1", ScriptedRawRpc::Mode::InitialDownload},
                {"http://backup2", ScriptedRawRpc::Mode::Warmup}};
    CHECK_THROWS_AS(rpc.getblocktemplate_parsed(), RpcConnectionError);
    CHECK(rpc.hits["http://primary"] == 1);
    CHECK(rpc.hits["http://backup1"] == 1);
    CHECK(rpc.hits["http://backup2"] == 1);
}

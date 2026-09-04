// Failover state-machine coverage for RpcClient::call() via a scripted call_one (no network).
// Invariants pinned:
//   * bitcoin_nodes[0] is primary; the rest are failover, tried in order.
//   * a connection failure advances to the next endpoint and STICKS there.
//   * RPC errors are final except -9/-10/-28, which mean the endpoint is temporarily unavailable.
//   * all endpoints down -> RpcConnectionError after trying each once.
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

// Drives call() without a network: each endpoint URL maps to a behaviour, and
// every attempt is counted so tests can assert exactly which nodes were tried.
class ScriptedRpc : public RpcClient {
public:
    enum class Mode { Ok, Down, WorkUnavailable, RpcErr };
    explicit ScriptedRpc(const std::vector<RpcEndpoint>& endpoints)
        : RpcClient(endpoints, /*timeout_seconds=*/1) {}

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
            throw RpcConnectionError("down: " + endpoint.url);
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
            throw RpcConnectionError("down: " + endpoint.url);
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

class BlockingFailbackRpc final : public RpcClient {
public:
    explicit BlockingFailbackRpc(const std::vector<RpcEndpoint>& endpoints)
        : RpcClient(endpoints, 1), release_signal_(release_primary.get_future().share()) {}

    std::atomic<bool> primary_available{false};
    std::atomic<int> backup_template_requests{0};
    std::promise<void> primary_called;
    std::promise<void> release_primary;

protected:
    glz::generic call_one(const Resolved& endpoint, const std::string&, long) override {
        if (endpoint.url == "http://primary" && !primary_available.load())
            throw RpcConnectionError("primary unavailable");
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
    CHECK(rpc.call("getblockcount")["served_by"].get<std::string>() =="http://primary");
    CHECK(rpc.hits["http://backup2"] == 1); // tried once on the wrap-around
}

namespace {

class SubmitRpc : public RpcClient {
public:
    enum class Reply {
        Accepted,
        Duplicate,
        Inconclusive,
        Rejected,
        BadPreviousBlock,
        Down,
        RpcError
    };

    explicit SubmitRpc(const std::vector<RpcEndpoint>& endpoints)
        : RpcClient(endpoints, /*timeout_seconds=*/1) {}

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
        case Reply::Down: throw RpcConnectionError("down: " + endpoint.url);
        case Reply::RpcError: throw erikslund::RpcError("submitblock denied", -22);
        }
        throw std::logic_error("unhandled submitblock reply");
    }

private:
    std::mutex mutex_;
    std::map<std::string, int> hits_;
};

class BlockingSubmitRpc : public RpcClient {
public:
    explicit BlockingSubmitRpc(const std::vector<RpcEndpoint>& endpoints)
        : RpcClient(endpoints, /*timeout_seconds=*/1),
          release_signal_(release_primary.get_future().share()) {}

    std::promise<void> primary_called;
    std::promise<void> backup_called;
    std::promise<void> release_primary;

protected:
    glz::generic call_one(const Resolved& endpoint, const std::string&, long) override {
        if (endpoint.url == "http://primary") {
            primary_called.set_value();
            release_signal_.wait();
            throw RpcConnectionError("primary timed out");
        }
        if (endpoint.url == "http://backup1") {
            backup_called.set_value();
            return glz::generic{};
        }
        return glz::generic(std::string("high-hash"));
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

// The raw GBT path parses directly into a BlockTemplate before publishing a new active endpoint.
namespace {

class ScriptedRawRpc : public RpcClient {
public:
    enum class Mode { Ok, Down, NotConnected, InitialDownload, Warmup, RpcErr, Garbage };
    explicit ScriptedRawRpc(const std::vector<RpcEndpoint>& endpoints)
        : RpcClient(endpoints, /*timeout_seconds=*/1) {}

    std::map<std::string, Mode> mode;
    std::map<std::string, int> hits;

protected:
    std::string post_one(const Resolved& endpoint, const std::string& /*payload*/, long /*timeout*/,
                         long* /*http_status*/) override {
        ++hits[endpoint.url];
        switch (mode.at(endpoint.url)) {
        case Mode::Down:
            throw RpcConnectionError("down: " + endpoint.url);
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
        case Mode::Ok:
            break;
        }
        return gbt_body(kTip);
    }
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

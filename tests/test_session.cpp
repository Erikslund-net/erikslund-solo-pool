#include <doctest/doctest.h>

#include <algorithm>
#include <ctime>
#include <format>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "bitcoin/block_template.hpp"
#include "gbt_fixture.hpp"
#include "stratum/job.hpp"
#include "stratum/session.hpp"
#include "util/difficulty.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::stratum;
using namespace erikslund::test;
using json = glz::generic;

namespace erikslund::stratum {
// Test-only window into Session's private dedup internals (friend of Session).
struct SessionTestPeek {
    static bool remember(Session& s, std::string key) { return s.remember(std::move(key)); }
    static size_t current_size(const Session& s) { return s.seen_shares_current_.size(); }
    static size_t previous_size(const Session& s) { return s.seen_shares_previous_.size(); }
};
} // namespace erikslund::stratum

namespace {

const Bytes kPayoutScript = util::from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
const Bytes kOtherPayoutScript = util::from_hex("00140000000000000000000000000000000000000001");

std::shared_ptr<Job> make_fake_job(uint32_t curtime) {
    gbt_json t = gbt_json::object_t{};
    t["height"] = 200;
    t["version"] = 0x20000000;
    t["curtime"] = curtime;
    t["bits"] = std::string("207fffff"); // regtest-easy, so a share is cheap to accept
    t["coinbasevalue"] = 5000000000LL;
    t["previousblockhash"] = std::string(64, '0');
    t["transactions"] = gbt_json::array_t{};
    const auto tmpl = from_template(t);
    const Bytes tag{'/', 'e', 'p', '/'};
    return std::make_shared<Job>("job1", tmpl, tag, 4, 4, 1);
}

class FakeConnection : public Connection {
public:
    std::vector<json> sent;
    void send_line(std::string_view line) override {
        json parsed;
        if (!glz::read_json(parsed, line)) // wire output is always valid JSON
            sent.push_back(std::move(parsed));
    }
    std::string peer() const override { return "test-peer"; }

    std::optional<json> by_id(double id) const {
        for (const auto& m : sent)
            if (m.contains("id") && m["id"].is_number() && m["id"].get<double>() == id)
                return std::make_optional(m); // explicit: json -> optional<json> is ambiguous
        return std::nullopt;
    }
    std::optional<json> by_method(std::string_view method) const {
        for (const auto& m : sent)
            if (m.contains("method") && m["method"].is_string() &&
                m["method"].get<std::string>() == method)
                return std::make_optional(m);
        return std::nullopt;
    }
};

class FakePool : public PoolContext {
public:
    std::shared_ptr<Job> job;
    int accepted = 0;
    int rejected = 0;
    std::optional<RejectClass> last_reject_class; // reason routing of the most recent reject
    double last_share_difficulty = 0.0;
    double last_share_best = 0.0;
    std::string last_share_address;
    std::string last_share_worker;
    bool block_found = false;
    std::function<void()> block_found_hook;
    bool vardiff = false;
    double minimum_difficulty = 0.001;
    double maximum_difficulty = 0.0;

    explicit FakePool(uint32_t curtime) : job(make_fake_job(curtime)) {}

    size_t extranonce2_size() const override { return 4; }
    std::shared_ptr<const RuntimeConfig> runtime_config() const override {
        Config config;
        config.initial_difficulty = 1e-9;
        config.minimum_difficulty = minimum_difficulty;
        config.maximum_difficulty = maximum_difficulty;
        config.variable_difficulty = vardiff;
        return std::make_shared<const RuntimeConfig>(config.runtime_config());
    }
    double start_difficulty() const { return runtime_config()->initial_difficulty; }
    std::optional<Bytes> validate_address(const std::string& address) override {
        if (address == "validaddr" || address == "VALIDADDR")
            return kPayoutScript;
        if (address == "othervalidaddr")
            return kOtherPayoutScript;
        return std::nullopt;
    }
    std::shared_ptr<const Job> current_job() const override { return job; }
    std::shared_ptr<const Job> recent_job(const std::string& job_id) const override {
        return (job && job->job_id() == job_id) ? job : nullptr;
    }
    std::vector<std::pair<std::string, std::string>> attached; // (address, worker) authorize log
    stats::WorkerAccountingHandle attach_worker(const std::string& address,
                                                const std::string& worker) override {
        attached.emplace_back(address, worker);
        return {};
    }
    void note_accepted_share(const std::string& address, const std::string& worker, double credited,
                             double share_difficulty) override {
        ++accepted;
        last_share_difficulty = credited;
        last_share_best = share_difficulty;
        last_share_address = address;
        last_share_worker = worker;
    }
    void note_rejected_share(const std::string&, const std::string&, RejectClass reason) override {
        ++rejected;
        last_reject_class = reason;
    }
    void on_block_found(const std::string&, const std::string&, const Job&,
                        const ShareResult&) override {
        block_found = true;
        if (block_found_hook)
            block_found_hook();
    }
    uint32_t version_mask() const override { return 0x1fffe000u; }
};

// Find a nonce whose share is accepted (the regtest-easy target accepts ~half).
std::string find_accepted_nonce(const Job& job, const Bytes& enonce1, double difficulty,
                                bool require_block = false) {
    const Bytes coinbase2 = job.build_coinbase2(kPayoutScript);
    for (uint32_t nonce = 0; nonce < 512; ++nonce) {
        ShareInput in;
        in.coinbase2 = coinbase2;
        in.extranonce1 = enonce1;
        in.extranonce2_hex = "01020304";
        in.ntime_hex = job.ntime_hex();
        const std::string nonce_hex = std::format("{:08x}", nonce);
        in.nonce_hex = nonce_hex;
        in.share_target = util::target_from_difficulty(difficulty);
        in.now_unix = static_cast<int64_t>(std::time(nullptr));
        const auto result = job.validate_share(in);
        if (result && (!require_block || result->is_block))
            return nonce_hex;
    }
    return "";
}

struct Fixture {
    uint32_t curtime = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool{curtime};
    FakeConnection conn;
    Session session{pool, conn, util::from_hex("e06ae06a")};

    void subscribe() {
        session.handle_line(R"({"id":1,"method":"mining.subscribe","params":["miner/1.0"]})");
    }
    void authorize(const std::string& user, std::string_view password = "x") {
        session.handle_line(
            std::format(R"({{"id":3,"method":"mining.authorize","params":["{}","{}"]}})",
                        user, password));
    }
};

} // namespace

TEST_CASE("subscribe returns enonce1 + enonce2 size and sets state") {
    Fixture f;
    f.subscribe();
    const auto reply = f.conn.by_id(1);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"][1].get<std::string>() == f.session.extranonce1_hex());
    CHECK((*reply)["result"][2].get<double>() == 4);
    CHECK(f.session.subscribed());
}

TEST_CASE("configure negotiates the version-rolling mask down to the server mask") {
    Fixture f;
    f.session.handle_line(
        R"({"id":2,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"ffffffff"}]})");
    const auto reply = f.conn.by_id(2);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"]["version-rolling"].get<bool>() == true);
    CHECK((*reply)["result"]["version-rolling.mask"].get<std::string>() == "1fffe000");
    CHECK(f.session.version_mask() == 0x1fffe000u);
}

TEST_CASE("configure answers version-rolling=false when the negotiated mask is empty") {
    // Client bits that don't overlap the server mask (0x1fffe000) -> empty intersection. BIP310:
    // answer false so the miner doesn't roll bits the pool would reject (and lose blocks on).
    Fixture f;
    f.session.handle_line(
        R"({"id":2,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"00000001"}]})");
    const auto reply = f.conn.by_id(2);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"]["version-rolling"].get<bool>() == false);
    CHECK((*reply)["result"]["version-rolling.mask"].get<std::string>() == "00000000");
    CHECK(f.session.version_mask() == 0u);
}

TEST_CASE("authorize accepts a valid address and pushes difficulty + a job") {
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.worker1");

    const auto reply = f.conn.by_id(3);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"].get<bool>() == true);
    CHECK(f.session.authorized());
    CHECK(f.session.address() == "validaddr");
    CHECK(f.conn.by_method("mining.set_difficulty").has_value());
    CHECK(f.conn.by_method("mining.notify").has_value());
}

TEST_CASE("authorize adopts password difficulty before sending initial work") {
    Fixture fixture;
    fixture.subscribe();
    fixture.authorize("validaddr.worker1", "d=1000000");

    CHECK(fixture.session.difficulty() == doctest::Approx(1'000'000.0));
    const auto difficulty = fixture.conn.by_method("mining.set_difficulty");
    REQUIRE(difficulty.has_value());
    CHECK((*difficulty)["params"][0].get<double>() == doctest::Approx(1'000'000.0));
    CHECK(fixture.conn.by_method("mining.notify").has_value());
}

TEST_CASE("authorize accepts diff password tokens and clamps them to the configured range") {
    Fixture fixture;
    fixture.pool.minimum_difficulty = 10.0;
    fixture.pool.maximum_difficulty = 500'000.0;
    fixture.authorize("validaddr.worker1", "c=BTC, diff=1000000");

    CHECK(fixture.session.difficulty() == doctest::Approx(500'000.0));
}

TEST_CASE("authorize accepts the MRR diff_ password difficulty") {
    Fixture fixture;
    fixture.authorize("validaddr.worker1", "diff_524000");

    CHECK(fixture.session.difficulty() == doctest::Approx(524'000.0));
}

TEST_CASE("authorize ignores malformed password difficulty") {
    Fixture fixture;
    const double initial_difficulty = fixture.session.difficulty();
    fixture.authorize("validaddr.worker1", "d=1000oops");

    CHECK(fixture.session.difficulty() == doctest::Approx(initial_difficulty));
}

TEST_CASE("authorize allows an empty or absent worker name (address only)") {
    {
        Fixture f; // no worker name at all: just the payout address, no dot
        f.subscribe();
        f.authorize("validaddr");
        const auto reply = f.conn.by_id(3);
        REQUIRE(reply.has_value());
        CHECK((*reply)["result"].get<bool>() == true);
        CHECK(f.session.authorized());
        CHECK(f.session.address() == "validaddr");
        CHECK(f.session.worker() == ""); // no worker name
    }
    {
        Fixture f; // empty worker name: a trailing dot
        f.subscribe();
        f.authorize("validaddr.");
        const auto reply = f.conn.by_id(3);
        REQUIRE(reply.has_value());
        CHECK((*reply)["result"].get<bool>() == true);
        CHECK(f.session.authorized());
        CHECK(f.session.address() == "validaddr");
        CHECK(f.session.worker() == ""); // empty worker name
    }
}

TEST_CASE("authorize rejects an invalid address") {
    Fixture f;
    f.subscribe();
    f.authorize("badaddr.worker1");
    const auto reply = f.conn.by_id(3);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"].get<bool>() == false);
    CHECK_FALSE(f.session.authorized());
}

TEST_CASE("re-authorize to a DIFFERENT payout address on one connection is refused") {
    // One SV1 connection carries one payout identity: mining.notify sends a single coinbase2 built
    // from the session payout script. Adopting a second address would credit -- and on a solved
    // block PAY -- the wrong miner for every share that followed.
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w1");
    REQUIRE(f.session.authorized());
    REQUIRE(f.session.address().has_value());
    const std::string first = *f.session.address();

    f.session.handle_line(
        R"({"id":9,"method":"mining.authorize","params":["othervalidaddr.w2","x"]})");
    const auto reply = f.conn.by_id(9);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"].get<bool>() == false);
    // The original identity survives intact.
    CHECK(f.session.authorized());
    CHECK(*f.session.address() == first);
    CHECK(*f.session.worker() == "w1");
    REQUIRE(f.pool.attached.size() == 1);
    CHECK(f.pool.attached.front().first == "validaddr");
    CHECK(f.pool.attached.front().second == "w1");
}

TEST_CASE("re-authorize to the SAME address rebinds the worker name") {
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w1");
    f.authorize("validaddr.w2");
    CHECK(f.session.authorized());
    CHECK(*f.session.address() == "validaddr");
    CHECK(*f.session.worker() == "w2"); // same payout address -> worker rebind still allowed
}

TEST_CASE("re-authorize preserves one accounting identity across equivalent address spellings") {
    Fixture fixture;
    fixture.subscribe();
    fixture.authorize("validaddr.w1");
    fixture.session.handle_line(
        R"({"id":9,"method":"mining.authorize","params":["VALIDADDR.w2","x"]})");

    const auto reply = fixture.conn.by_id(9);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"].get<bool>() == true);
    CHECK(*fixture.session.address() == "validaddr");
    CHECK(*fixture.session.worker() == "w2");
    REQUIRE(fixture.pool.attached.size() == 2);
    CHECK(fixture.pool.attached.back().first == "validaddr");
    CHECK(fixture.pool.attached.back().second == "w2");
}

TEST_CASE("a submit username does not replace the connection's authorized identity") {
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w");
    f.session.handle_line(
        R"({"id":41,"method":"mining.submit","params":["othervalidaddr.w","nope","01020304","00000000","00000000"]})");
    const auto reply = f.conn.by_id(41);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0].get<double>() == 21); // stale, not unauthorized
}

TEST_CASE("submit before authorize is rejected as unauthorized") {
    Fixture f;
    f.subscribe();
    f.session.handle_line(
        R"({"id":4,"method":"mining.submit","params":["w","job1","01020304","00000000","00000000"]})");
    const auto reply = f.conn.by_id(4);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0].get<double>() == 24); // unauthorized
}

TEST_CASE("submit to an unknown job is stale") {
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w");
    f.session.handle_line(
        R"({"id":5,"method":"mining.submit","params":["w","nope","01020304","00000000","00000000"]})");
    const auto reply = f.conn.by_id(5);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0].get<double>() == 21); // stale
}

TEST_CASE("a valid block share with mismatched username is dispatched, counted, and deduplicated") {
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w");

    bool dispatched = false;
    f.pool.block_found_hook = [&] {
        dispatched = true;
        CHECK(f.pool.accepted == 0);
        CHECK(f.session.shares_accepted() == 0);
        CHECK_FALSE(f.conn.by_id(6).has_value());
    };
    const std::string nonce = find_accepted_nonce(
        *f.pool.job, util::from_hex("e06ae06a"), f.pool.start_difficulty(), true);
    REQUIRE_FALSE(nonce.empty());

    const std::string submit = std::format(
        R"({{"id":6,"method":"mining.submit","params":["othervalidaddr.w","job1","01020304","{}","{}"]}})",
        f.pool.job->ntime_hex(), nonce);

    f.session.handle_line(submit);
    const auto first = f.conn.by_id(6);
    REQUIRE(first.has_value());
    CHECK((*first)["result"].get<bool>() == true);
    CHECK(dispatched);
    CHECK(f.pool.accepted == 1);
    CHECK(f.session.shares_accepted() == 1);

    // Exact resubmit -> duplicate.
    f.conn.sent.clear();
    f.session.handle_line(submit);
    const auto second = f.conn.by_id(6);
    REQUIRE(second.has_value());
    CHECK((*second)["error"][0].get<double>() == 22); // duplicate
    CHECK(f.pool.accepted == 1);        // not double-counted
    CHECK(f.pool.rejected == 1);        // the duplicate was counted as rejected
}

TEST_CASE("a duplicate resubmitted across a clean job is still rejected (generation lookback)") {
    // recent_jobs keeps accepting old-job shares for the whole late-share window, so a duplicate
    // arriving just after a clean notify must still be caught (clean must not clear the dedup set).
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w");

    const std::string nonce =
        find_accepted_nonce(*f.pool.job, util::from_hex("e06ae06a"), f.pool.start_difficulty());
    REQUIRE_FALSE(nonce.empty());
    const std::string submit = std::format(
        R"({{"id":6,"method":"mining.submit","params":["w","job1","01020304","{}","{}"]}})",
        f.pool.job->ntime_hex(), nonce);

    f.session.handle_line(submit);
    REQUIRE(f.conn.by_id(6).has_value());
    CHECK((*f.conn.by_id(6))["result"].get<bool>() == true);

    f.session.send_notify(*f.pool.job, /*clean=*/true); // rotation point (new clean work)

    f.conn.sent.clear();
    f.session.handle_line(submit);
    const auto replay = f.conn.by_id(6);
    REQUIRE(replay.has_value());
    CHECK((*replay)["error"][0].get<double>() == 22); // still a duplicate, not double-credited
    CHECK(f.pool.accepted == 1);
}

TEST_CASE("seen-shares cap rotation keeps one lookback generation (size-triggered)") {
    // The size-triggered rotation (vs the clean-notify one): at kMaxSeenShares the live set
    // becomes the lookback set instead of being cleared, so a key from the rotated-out generation
    // is still caught. Guards against a future refactor turning the cap rotate back into clear().
    Fixture f;
    for (size_t i = 0; i < kMaxSeenShares; ++i)
        CHECK(SessionTestPeek::remember(f.session, std::format("k{}", i)));
    CHECK(SessionTestPeek::current_size(f.session) == kMaxSeenShares);
    CHECK(SessionTestPeek::previous_size(f.session) == 0);

    // One more distinct key trips the cap: current -> previous, fresh current holds only the new.
    CHECK(SessionTestPeek::remember(f.session, "overflow"));
    CHECK(SessionTestPeek::current_size(f.session) == 1);
    CHECK(SessionTestPeek::previous_size(f.session) == kMaxSeenShares);

    // A key from the demoted generation is still a duplicate (caught via the lookback set)...
    CHECK_FALSE(SessionTestPeek::remember(f.session, "k0"));
    // ...and a genuinely new key is still accepted.
    CHECK(SessionTestPeek::remember(f.session, "brand-new"));
}

TEST_CASE("the duplicate guard is insensitive to hex casing (same canonical share)") {
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w");

    const std::string nonce =
        find_accepted_nonce(*f.pool.job, util::from_hex("e06ae06a"), f.pool.start_difficulty());
    REQUIRE_FALSE(nonce.empty());
    const std::string ntime = f.pool.job->ntime_hex();

    f.session.handle_line(std::format(
        R"({{"id":6,"method":"mining.submit","params":["w","job1","01020304","{}","{}"]}})", ntime,
        nonce));
    REQUIRE(f.conn.by_id(6).has_value());
    CHECK((*f.conn.by_id(6))["result"].get<bool>() == true);

    // Resubmit the identical share with the hex fields upper-cased. It is the same work, so the
    // canonical dedup key must match and the resubmit must be rejected as a duplicate (not credited).
    auto upper = [](std::string s) {
        for (char& c : s)
            if (c >= 'a' && c <= 'f')
                c = static_cast<char>(c - 32);
        return s;
    };
    f.conn.sent.clear();
    f.session.handle_line(std::format(
        R"({{"id":7,"method":"mining.submit","params":["w","job1","01020304","{}","{}"]}})",
        upper(ntime), upper(nonce)));
    const auto dup = f.conn.by_id(7);
    REQUIRE(dup.has_value());
    CHECK((*dup)["error"][0].get<double>() == 22); // duplicate despite the different spelling
    CHECK(f.pool.accepted == 1);     // the upper-cased resubmit was NOT counted again
}

TEST_CASE("a short malformed extranonce2 does not shadow a valid full-width share") {
    // extranonce2's length is meaningful, so the dedup key must NOT zero-pad it: a too-short
    // (invalid) extranonce2 recorded before validation must not collide with a later valid
    // full-width share whose value equals the padded form -- that share could be a block.
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w");
    const std::string ntime = f.pool.job->ntime_hex();

    // 2-byte extranonce2 (expected 4): rejected for size, but its dedup key is recorded first.
    f.session.handle_line(std::format(
        R"({{"id":1,"method":"mining.submit","params":["w","job1","0102","{}","00000000"]}})", ntime));

    // A valid-width extranonce2 whose zero-padded form equals the short one above. Under a padding
    // key this collided (-> false duplicate); it must now be processed as its own share (never 22).
    f.conn.sent.clear();
    f.session.handle_line(std::format(
        R"({{"id":2,"method":"mining.submit","params":["w","job1","00000102","{}","00000000"]}})",
        ntime));
    const auto second = f.conn.by_id(2);
    REQUIRE(second.has_value());
    const bool is_duplicate =
        !(*second)["error"].is_null() && (*second)["error"][0].get<double>() == 22;
    CHECK_FALSE(is_duplicate);
}

TEST_CASE("a difficulty change takes effect only from the next job (grace window)") {
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w");
    const Bytes enonce1 = util::from_hex("e06ae06a");
    const double start_diff = f.session.difficulty(); // clamped start difficulty

    // Three distinct accepted nonces (the regtest-easy network target accepts ~half), so each
    // submit has its own dedup key without an intervening clean job.
    std::vector<std::string> nonces;
    const Bytes coinbase2 = f.pool.job->build_coinbase2(kPayoutScript);
    for (uint32_t n = 0; n < 4096 && nonces.size() < 3; ++n) {
        const std::string nonce_hex = std::format("{:08x}", n);
        ShareInput in;
        in.coinbase2 = coinbase2;
        in.extranonce1 = enonce1;
        in.extranonce2_hex = "01020304";
        in.ntime_hex = f.pool.job->ntime_hex();
        in.nonce_hex = nonce_hex;
        in.share_target = util::target_from_difficulty(start_diff);
        in.now_unix = static_cast<int64_t>(std::time(nullptr));
        if (f.pool.job->validate_share(in).has_value())
            nonces.push_back(nonce_hex);
    }
    REQUIRE(nonces.size() == 3);

    const auto submit = [&](int id, const std::string& nonce) {
        f.conn.sent.clear();
        f.session.handle_line(std::format(
            R"({{"id":{},"method":"mining.submit","params":["w","job1","01020304","{}","{}"]}})", id,
            f.pool.job->ntime_hex(), nonce));
    };

    // Baseline: no pending change -> credited at the current difficulty.
    submit(10, nonces[0]);
    CHECK((*f.conn.by_id(10))["result"].get<bool>() == true);
    CHECK(f.pool.last_share_difficulty == doctest::Approx(start_diff));

    // Raise difficulty far above the share's actual difficulty, with NO new job. The in-flight
    // share is still accepted and credited at the OLD difficulty -- not the new one.
    const double high = start_diff * 1e6;
    f.session.handle_line(
        std::format(R"({{"id":11,"method":"mining.suggest_difficulty","params":[{}]}})", high));
    CHECK(f.session.difficulty() == doctest::Approx(high)); // advertised value changed immediately
    submit(12, nonces[1]);
    CHECK((*f.conn.by_id(12))["result"].get<bool>() == true); // accepted, not "above target"
    CHECK(f.pool.last_share_difficulty == doctest::Approx(start_diff)); // credited the OLD difficulty

    // The next job ends the grace window; subsequent shares credit the NEW difficulty.
    f.session.send_notify(*f.pool.job, /*clean=*/true);
    submit(13, nonces[2]);
    CHECK((*f.conn.by_id(13))["result"].get<bool>() == true);
    CHECK(f.pool.last_share_difficulty == doctest::Approx(high)); // credited the NEW difficulty
}

TEST_CASE("difficulty-grace crediting: LOWER direction and the meets-the-harder-target branch") {
    // The base grace test only RAISES, and every in-flight share credits the easier (lo) value.
    // This drives a LOWER change (previous > new, so hi=previous, lo=new -- the min/max swap) and
    // asserts BOTH credit branches: a share that meets the harder old target credits at hi, an
    // easier one at lo. A low floor lets us put real share difficulties on both sides of hi (the
    // default fixture clamps the start up to min_difficulty, leaving no room below it).
    struct LowFloorPool : FakePool {
        using FakePool::FakePool;
        std::shared_ptr<const RuntimeConfig> runtime_config() const override {
            Config config;
            config.initial_difficulty = 1e-9;
            config.minimum_difficulty = 1e-12;
            config.variable_difficulty = vardiff;
            return std::make_shared<const RuntimeConfig>(config.runtime_config());
        }
    };
    const uint32_t curtime = static_cast<uint32_t>(std::time(nullptr));
    LowFloorPool pool{curtime};
    FakeConnection conn;
    Session session{pool, conn, util::from_hex("e06ae06a")};
    session.handle_line(R"({"id":1,"method":"mining.subscribe","params":["miner/1.0"]})");
    session.handle_line(R"({"id":3,"method":"mining.authorize","params":["validaddr.w","x"]})");

    // Both difficulties stay above the target_from_difficulty 256-bit overflow floor (~2.3e-10) so
    // the accept target is well-formed; the regtest-easy job yields share difficulties spanning hi.
    const double hi = session.difficulty(); // == clamped start (1e-9); becomes previous_ on the lower
    const double lo = 5e-10;                // the new (lower) difficulty
    REQUIRE(hi > lo);

    // Measure each nonce's actual share difficulty (loosest target => always reports one) and pick
    // one at/above hi (meets the harder old target) and one in [lo, hi) (only meets the easier new
    // one) -- both >= lo, so both are accepted under the new (min) target.
    const Bytes enonce1 = util::from_hex("e06ae06a");
    const Bytes coinbase2 = pool.job->build_coinbase2(kPayoutScript);
    const auto difficulty_of = [&](uint32_t nonce, std::string& nonce_hex) {
        nonce_hex = std::format("{:08x}", nonce);
        ShareInput in;
        in.coinbase2 = coinbase2;
        in.extranonce1 = enonce1;
        in.extranonce2_hex = "01020304";
        in.ntime_hex = pool.job->ntime_hex();
        in.nonce_hex = nonce_hex;
        in.share_target = util::uint256::from_display_hex(std::string(64, 'f')); // loosest: always valid
        in.now_unix = static_cast<int64_t>(std::time(nullptr));
        const auto result = pool.job->validate_share(in);
        return result ? result->difficulty : result.error().difficulty;
    };
    std::string lucky;
    std::string easy;
    for (uint32_t n = 0; n < 16384 && (lucky.empty() || easy.empty()); ++n) {
        std::string nonce_hex;
        const double d = difficulty_of(n, nonce_hex);
        if (lucky.empty() && d >= hi)
            lucky = nonce_hex;
        else if (easy.empty() && d >= lo && d < hi)
            easy = nonce_hex;
    }
    REQUIRE_FALSE(lucky.empty());
    REQUIRE_FALSE(easy.empty());

    // Lower the difficulty (hi -> lo) with NO new job: now pending, previous_=hi > difficulty_=lo.
    session.handle_line(
        std::format(R"({{"id":20,"method":"mining.suggest_difficulty","params":[{}]}})", lo));
    REQUIRE(session.difficulty() == doctest::Approx(lo)); // advertised immediately

    const auto submit = [&](int id, const std::string& nonce) {
        conn.sent.clear();
        session.handle_line(std::format(
            R"({{"id":{},"method":"mining.submit","params":["w","job1","01020304","{}","{}"]}})", id,
            pool.job->ntime_hex(), nonce));
    };

    // A share meeting the harder OLD target credits at hi (= previous), not the new lo -- this is
    // the `result.difficulty >= hi ? hi : lo` true branch the base test never reaches.
    submit(21, lucky);
    CHECK((*conn.by_id(21))["result"].get<bool>() == true);
    CHECK(pool.last_share_difficulty == doctest::Approx(hi));

    // A share that only meets the easier NEW target credits at lo.
    submit(22, easy);
    CHECK((*conn.by_id(22))["result"].get<bool>() == true);
    CHECK(pool.last_share_difficulty == doctest::Approx(lo));
}

TEST_CASE("a valid share clears the accumulated protocol-error budget") {
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w");

    // Two malformed submits (<5 params) -> ERR_OTHER each -> the budget climbs.
    f.session.handle_line(R"({"id":1,"method":"mining.submit","params":["w"]})");
    f.session.handle_line(R"({"id":2,"method":"mining.submit","params":["w"]})");
    CHECK(f.session.protocol_errors() == 2);

    // A genuinely valid share resets it to zero (sustained garbage, not lifetime).
    const std::string nonce =
        find_accepted_nonce(*f.pool.job, util::from_hex("e06ae06a"), f.pool.start_difficulty());
    REQUIRE_FALSE(nonce.empty());
    const std::string submit = std::format(
        R"({{"id":3,"method":"mining.submit","params":["w","job1","01020304","{}","{}"]}})",
        f.pool.job->ntime_hex(), nonce);
    f.session.handle_line(submit);
    REQUIRE(f.conn.by_id(3).has_value());
    CHECK(f.conn.by_id(3).value()["result"].get<bool>() == true);
    CHECK(f.session.protocol_errors() == 0);
}

TEST_CASE("vardiff_next decision and clamps") {
    // target 12 spm: faster than 2x doubles, slower than half halves, else holds.
    CHECK(vardiff_next(100, 30, 12, 0.001, 0) == doctest::Approx(200));    // too fast -> double
    CHECK(vardiff_next(100, 3, 12, 0.001, 0) == doctest::Approx(50));      // too slow -> halve
    CHECK(vardiff_next(100, 12, 12, 0.001, 0) == doctest::Approx(100));    // in band -> hold
    CHECK(vardiff_next(0.001, 0, 12, 0.001, 0) == doctest::Approx(0.001)); // halve clamped to min
    CHECK(vardiff_next(1000, 99, 12, 0.001, 2000) == doctest::Approx(2000)); // double clamped to max
    CHECK(vardiff_next(2000, 99, 12, 0.001, 2000) == doctest::Approx(2000)); // already at max -> hold
}

TEST_CASE("vardiff_next band edges hold (strict comparisons)") {
    // Exactly 2x target is NOT "> 2x", so it holds rather than doubling.
    CHECK(vardiff_next(100, 24, 12, 0.001, 0) == doctest::Approx(100));
    // Exactly half target is NOT "< half", so it holds rather than halving.
    CHECK(vardiff_next(100, 6, 12, 0.001, 0) == doctest::Approx(100));
    // Just over 2x doubles; just under half halves.
    CHECK(vardiff_next(100, 24.01, 12, 0.001, 0) == doctest::Approx(200));
    CHECK(vardiff_next(100, 5.99, 12, 0.001, 0) == doctest::Approx(50));
}

TEST_CASE("vardiff_next never exceeds the implicit 1e12 cap when no max is set") {
    // current already at the implicit cap: a fast rate cannot push it higher.
    CHECK(vardiff_next(1e12, 1000, 12, 0.001, 0) == doctest::Approx(1e12));
}

TEST_CASE("vardiff_next applies changed bounds while the share rate is in band") {
    CHECK(vardiff_next(1.0, 12.0, 12.0, 4.0, 100.0) == doctest::Approx(4.0));
    CHECK(vardiff_next(200.0, 12.0, 12.0, 1.0, 100.0) == doctest::Approx(100.0));
}

TEST_CASE("clamp_suggested_difficulty rejects NaN") {
    CHECK_FALSE(
        clamp_suggested_difficulty(std::numeric_limits<double>::quiet_NaN(), 1, 0).has_value());
}

TEST_CASE("clamp_suggested_difficulty clamps to the configured band") {
    CHECK(*clamp_suggested_difficulty(64, 1, 0) == doctest::Approx(64));        // in band, no max
    CHECK(*clamp_suggested_difficulty(0.5, 1, 0) == doctest::Approx(1));        // below min -> min
    CHECK(*clamp_suggested_difficulty(1e9, 1, 1000) == doctest::Approx(1000));  // above max -> max
    CHECK_FALSE(clamp_suggested_difficulty(0, 1, 0).has_value());              // non-positive -> reject
    CHECK_FALSE(clamp_suggested_difficulty(-5, 1, 0).has_value());             // negative -> reject
    CHECK_FALSE(clamp_suggested_difficulty(                                    // non-finite -> reject
                    std::numeric_limits<double>::infinity(), 1, 0)
                    .has_value());
}

TEST_CASE("suggest_difficulty adopts the clamped value and pushes set_difficulty") {
    Fixture f;
    f.subscribe();
    f.conn.sent.clear();
    f.session.handle_line(R"({"id":9,"method":"mining.suggest_difficulty","params":[256]})");

    const auto reply = f.conn.by_id(9);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"].get<bool>() == true);
    CHECK(f.session.difficulty() == doctest::Approx(256.0)); // FakePool min 0.001, no max
    const auto setdiff = f.conn.by_method("mining.set_difficulty");
    REQUIRE(setdiff.has_value());
    CHECK((*setdiff)["params"][0].get<double>() == doctest::Approx(256.0));
}

TEST_CASE("suggest_difficulty with a non-positive value is acked but ignored") {
    Fixture f;
    f.subscribe();
    const double before = f.session.difficulty();
    f.session.handle_line(R"({"id":10,"method":"mining.suggest_difficulty","params":[0]})");

    const auto reply = f.conn.by_id(10);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"].get<bool>() == true);            // still acknowledged
    CHECK(f.session.difficulty() == doctest::Approx(before)); // difficulty unchanged (no zero-out)
}

TEST_CASE("configure echoes false for a requested extension it does not support (BIP310)") {
    Fixture f;
    f.session.handle_line(
        R"({"id":2,"method":"mining.configure","params":[["minimum-difficulty"],{"minimum-difficulty.value":16}]})");
    const auto reply = f.conn.by_id(2);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"].is_object());
    CHECK((*reply)["result"]["minimum-difficulty"].get<bool>() == false); // requested but unsupported
    CHECK(f.session.version_mask() == 0u); // version-rolling not requested
}

TEST_CASE("configure with a malformed mask negotiates an empty (zero) mask -> rolling disabled") {
    // A malformed mask parses to 0, so the intersection is empty. BIP310: answer false (not true)
    // so the miner doesn't roll bits the pool would reject (true + mask 0 silently loses blocks).
    Fixture f;
    f.session.handle_line(
        R"({"id":2,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"nothex"}]})");
    const auto reply = f.conn.by_id(2);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"]["version-rolling"].get<bool>() == false);
    CHECK((*reply)["result"]["version-rolling.mask"].get<std::string>() == "00000000");
    CHECK(f.session.version_mask() == 0u);
}

TEST_CASE("configure with no mask field defaults the client to all-ones, capped to the server mask") {
    Fixture f;
    f.session.handle_line(
        R"({"id":2,"method":"mining.configure","params":[["version-rolling"],{}]})");
    const auto reply = f.conn.by_id(2);
    REQUIRE(reply.has_value());
    // client_mask 0xffffffff & server 0x1fffe000 = 0x1fffe000.
    CHECK((*reply)["result"]["version-rolling.mask"].get<std::string>() == "1fffe000");
    CHECK(f.session.version_mask() == 0x1fffe000u);
}

TEST_CASE("every present-but-invalid version-rolling mask disables rolling (mask 0)") {
    // A PRESENT mask key whose value isn't strict 1-8 char hex disables rolling. This is distinct
    // from an ABSENT key (previous test: defaults to the full pool mask). The empty/9-char/number/
    // null cases below are the precise inputs the strict guard + present-vs-absent split exist for.
    auto expect_disabled = [](const char* mask_param) {
        Fixture f;
        f.session.handle_line(std::format(
            R"({{"id":2,"method":"mining.configure","params":[["version-rolling"],{{"version-rolling.mask":{}}}]}})",
            mask_param));
        const auto reply = f.conn.by_id(2);
        REQUIRE(reply.has_value());
        CHECK((*reply)["result"]["version-rolling"].get<bool>() == false);
        CHECK((*reply)["result"]["version-rolling.mask"].get<std::string>() == "00000000");
        CHECK(f.session.version_mask() == 0u);
    };
    SUBCASE("empty string") { expect_disabled(R"("")"); }
    SUBCASE("9 hex chars (over-wide -- guards std::stoul accepting a too-large value)") {
        expect_disabled(R"("1fffe0000")");
    }
    SUBCASE("JSON number (present but non-string)") { expect_disabled("536813568"); }
    SUBCASE("explicit JSON null (present-null must NOT be treated as absent)") {
        expect_disabled("null");
    }
}

TEST_CASE("an unknown method is answered with ERR_OTHER but does NOT count toward the budget") {
    // Benign legacy methods (mining.ping, get_transactions, multi_version, ...) from real firmware
    // must not get a healthy miner dropped, so the error reply is sent without charging the budget.
    Fixture f;
    f.subscribe();
    f.session.handle_line(R"({"id":7,"method":"mining.ping","params":[]})");
    f.session.handle_line(R"({"id":8,"method":"get_transactions","params":[]})");
    const auto reply = f.conn.by_id(7);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0].get<double>() == 20); // ERR_OTHER, still answered
    CHECK(f.session.protocol_errors() == 0);
}

TEST_CASE("duplicate and older pool publications are skipped") {
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w");
    f.conn.sent.clear();

    const auto newer = make_fake_job(f.curtime);
    newer->set_publication_sequence(6);
    const auto older = make_fake_job(f.curtime);
    older->set_publication_sequence(5);

    f.session.send_notify(*newer, /*clean=*/true);
    f.session.send_notify(*newer, /*clean=*/true);
    f.session.send_notify(*older, /*clean=*/true);
    const auto notifies = std::count_if(f.conn.sent.begin(), f.conn.sent.end(), [](const json& m) {
        return m.contains("method") && m["method"].is_string() &&
               m["method"].get<std::string>() == "mining.notify";
    });
    CHECK(notifies == 1);

    const auto unstamped = make_fake_job(f.curtime);
    f.session.send_notify(*unstamped, /*clean=*/false);
    const auto after = std::count_if(f.conn.sent.begin(), f.conn.sent.end(), [](const json& m) {
        return m.contains("method") && m["method"].is_string() &&
               m["method"].get<std::string>() == "mining.notify";
    });
    CHECK(after == 2);
}

TEST_CASE("subscribe after authorize immediately pushes difficulty + a single clean job") {
    // Unusual order: a client that authorizes BEFORE subscribing has no work yet. On subscribe the
    // pool sends set_difficulty + a clean notify so work flows immediately. The authorize-time
    // notify is a no-op (not yet subscribed), so exactly one notify must be sent -- no double work.
    Fixture f;
    f.authorize("validaddr.w");
    REQUIRE(f.session.authorized());
    f.subscribe();
    REQUIRE(f.conn.by_id(1).has_value()); // subscribe reply
    CHECK(f.conn.by_method("mining.set_difficulty").has_value());
    const auto notify = f.conn.by_method("mining.notify");
    REQUIRE(notify.has_value());
    CHECK((*notify)["params"][8].get<bool>() == true); // clean_jobs flag
    const auto notifies = std::count_if(f.conn.sent.begin(), f.conn.sent.end(), [](const json& m) {
        return m.contains("method") && m["method"].is_string() &&
               m["method"].get<std::string>() == "mining.notify";
    });
    CHECK(notifies == 1);
}

TEST_CASE("authorize requires a non-empty username") {
    Fixture f;
    f.subscribe();
    f.session.handle_line(R"({"id":3,"method":"mining.authorize","params":[""]})");
    const auto reply = f.conn.by_id(3);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0].get<double>() == 20); // ERR_OTHER
    CHECK_FALSE(f.session.authorized());
}

TEST_CASE("submit with too few params is an other-error") {
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w");
    f.session.handle_line(R"({"id":7,"method":"mining.submit","params":["w","job1"]})");
    const auto reply = f.conn.by_id(7);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0].get<double>() == 20); // ERR_OTHER (needs >= 5 params)
}

TEST_CASE("mining.extranonce.subscribe is answered false, matching mining.configure") {
    Fixture f;
    f.subscribe();
    f.session.handle_line(R"({"id":11,"method":"mining.extranonce.subscribe","params":[]})");
    const auto reply = f.conn.by_id(11);
    REQUIRE(reply.has_value());
    // The pool never sends mining.set_extranonce, and handle_configure reports
    // subscribe-extranonce false; a bare true here would contradict that.
    CHECK((*reply)["result"].get<bool>() == false);
}

TEST_CASE("an unknown method with an id gets an other-error; with a null id, silence") {
    Fixture f;
    f.subscribe();
    f.conn.sent.clear();
    f.session.handle_line(R"({"id":12,"method":"mining.unheard_of","params":[]})");
    const auto reply = f.conn.by_id(12);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0].get<double>() == 20);

    // A notification-style call (null id) produces no response at all.
    f.conn.sent.clear();
    f.session.handle_line(R"({"method":"mining.unheard_of","params":[]})");
    CHECK(f.conn.sent.empty());
}

TEST_CASE("garbage input is silently ignored (no crash, no reply)") {
    Fixture f;
    f.conn.sent.clear();
    f.session.handle_line("this is not json");
    f.session.handle_line("");
    CHECK(f.conn.sent.empty());
}

TEST_CASE("stats() reflects subscribe/authorize and accepted shares") {
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.worker9");

    const std::string nonce =
        find_accepted_nonce(*f.pool.job, util::from_hex("e06ae06a"), f.pool.start_difficulty());
    REQUIRE_FALSE(nonce.empty());
    f.session.handle_line(std::format(
        R"({{"id":6,"method":"mining.submit","params":["w","job1","01020304","{}","{}"]}})",
        f.pool.job->ntime_hex(), nonce));

    const auto snapshot = f.session.stats();
    CHECK(snapshot.subscribed);
    CHECK(snapshot.authorized);
    CHECK(snapshot.address == "validaddr");
    CHECK(snapshot.worker == "worker9"); // worker name is the suffix after the first dot
    CHECK(snapshot.user_agent == "miner/1.0");
    CHECK(snapshot.shares_accepted == 1);
    CHECK(snapshot.best_difficulty > 0.0);
    CHECK(snapshot.last_share_timestamp > 0);
}

TEST_CASE("external send_notify pushes a mining.notify once subscribed + authorized") {
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w");
    f.conn.sent.clear();
    f.session.send_notify(*f.pool.job, /*clean=*/true);
    const auto notify = f.conn.by_method("mining.notify");
    REQUIRE(notify.has_value());
    // params: [job_id, prevhash, coinbase1, coinbase2, branch, version, nbits, ntime, clean].
    CHECK((*notify)["params"][0].get<std::string>() == "job1");
    CHECK((*notify)["params"][8].get<bool>() == true); // clean flag
}

TEST_CASE("send_notify is a no-op for an unauthorized session") {
    Fixture f;
    f.subscribe(); // subscribed but not authorized
    f.conn.sent.clear();
    f.session.send_notify(*f.pool.job, true);
    CHECK_FALSE(f.conn.by_method("mining.notify").has_value());
}

TEST_CASE("maybe_retarget does nothing when vardiff is disabled") {
    Fixture f; // FakePool.vardiff defaults to false
    f.subscribe();
    f.authorize("validaddr.w");
    f.conn.sent.clear();
    f.session.maybe_retarget();
    CHECK(f.conn.sent.empty()); // no set_difficulty pushed
}

TEST_CASE("send_set_difficulty pushes the current difficulty") {
    Fixture f;
    f.subscribe();
    f.conn.sent.clear();
    f.session.send_set_difficulty();
    const auto setdiff = f.conn.by_method("mining.set_difficulty");
    REQUIRE(setdiff.has_value());
    CHECK((*setdiff)["params"][0].get<double>() == doctest::Approx(f.session.difficulty()));
}

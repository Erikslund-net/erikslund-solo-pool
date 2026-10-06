#include <doctest/doctest.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <ctime>
#include <format>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
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
// Test-only window into Session's dedup, control-rate, and retarget timing state.
struct SessionTestPeek {
    static bool remember(Session& s, std::string key) { return s.remember(std::move(key)); }
    static size_t current_size(const Session& s) { return s.seen_shares_current_.size(); }
    static size_t previous_size(const Session& s) { return s.seen_shares_previous_.size(); }
    static size_t control_burst() { return static_cast<size_t>(Session::kControlRequestBurst); }
    static auto control_time(const Session& session) { return session.control_refill_at_; }
    static bool allow_control(Session& session, std::chrono::steady_clock::time_point now) {
        return session.allow_control_request(now);
    }
    static void freeze_control_refill(Session& session) {
        session.control_refill_at_ = std::chrono::steady_clock::time_point::max();
    }
    static void set_retarget_window(Session& session, uint64_t shares) {
        constexpr double kElapsedSeconds = 120.0;
        session.last_retarget_ = stats::steady_seconds() - kElapsedSeconds;
        session.shares_since_retarget_ = shares;
    }
    static double set_fixed_share_window(Session& session, double elapsed, uint64_t accepted) {
        const double now = stats::steady_seconds();
        session.fixed_share_window_started_ = now - elapsed;
        session.fixed_shares_in_window_ = accepted;
        return now;
    }
    static auto fixed_share_window(const Session& session) {
        return std::pair{session.fixed_share_window_started_, session.fixed_shares_in_window_};
    }
    static double fixed_difficulty_floor(const Session& session) {
        return session.fixed_difficulty_floor_;
    }
    static void evaluate_fixed_share_window(Session& session, double now) {
        session.maybe_raise_fixed_difficulty(now);
    }
};
} // namespace erikslund::stratum

namespace {

const Bytes kPayoutScript = util::from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
const Bytes kOtherPayoutScript = util::from_hex("00140000000000000000000000000000000000000001");

std::shared_ptr<Job> make_fake_job(uint32_t curtime, uint32_t version = 0x20000000,
                                 std::string_view bits = "01010000") {
    gbt_json t = gbt_json::object_t{};
    t["height"] = 200;
    t["version"] = version;
    t["curtime"] = curtime;
    t["bits"] = std::string(bits);
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
    double initial_difficulty = 1e-9;
    double minimum_difficulty = 1e-12;
    double maximum_difficulty = 0.0;

    explicit FakePool(uint32_t curtime, bool easy_blocks = false)
        : job(make_fake_job(curtime, 0x20000000, easy_blocks ? "207fffff" : "01010000")) {}

    size_t extranonce2_size() const override { return 4; }
    std::shared_ptr<const RuntimeConfig> runtime_config() const override {
        Config config;
        config.initial_difficulty = initial_difficulty;
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

// Tiny share difficulties and regtest block targets both make nonce search cheap.
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
    FakePool pool;
    FakeConnection conn;
    Session session{pool, conn, util::from_hex("e06ae06a")};

    explicit Fixture(bool easy_blocks = false) : pool(curtime, easy_blocks) {}

    void subscribe() {
        session.handle_line(R"({"id":1,"method":"mining.subscribe","params":["miner/1.0"]})");
    }
    void authorize(const std::string& user, std::string_view password = "x") {
        session.handle_line(
            std::format(R"({{"id":3,"method":"mining.authorize","params":["{}","{}"]}})",
                        user, password));
    }
    void configure_mask(std::string_view mask) {
        session.handle_line(std::format(
            R"({{"id":2,"method":"mining.configure","params":[["version-rolling"],{{"version-rolling.mask":"{}"}}]}})",
            mask));
    }
    void submit(int id, std::string_view nonce,
                std::optional<std::string_view> version_bits = std::nullopt) {
        const std::string version = version_bits ? std::format(",\"{}\"", *version_bits) : "";
        session.handle_line(std::format(
            R"({{"id":{},"method":"mining.submit","params":["w","job1","01020304","{}","{}"{}]}})",
            id, pool.job->ntime_hex(), nonce, version));
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

TEST_CASE("password difficulty tokens remain fixed at high and low share rates") {
    constexpr uint64_t kHighShareCount = 128;
    for (const std::string_view password : {"d=64", "diff=64", "diff_64"}) {
        CAPTURE(password);
        Fixture fixture;
        fixture.pool.vardiff = true;
        fixture.subscribe();
        fixture.authorize("validaddr.worker", password);
        REQUIRE(fixture.session.difficulty() == doctest::Approx(64.0));

        for (const uint64_t shares : {kHighShareCount, uint64_t{0}}) {
            fixture.conn.sent.clear();
            SessionTestPeek::set_retarget_window(fixture.session, shares);
            fixture.session.maybe_retarget();
            CHECK(fixture.session.difficulty() == doctest::Approx(64.0));
            CHECK(fixture.conn.sent.empty());
        }
    }
}

TEST_CASE("a password difficulty equal to the current value still disables VarDiff") {
    Fixture fixture;
    fixture.pool.vardiff = true;
    fixture.subscribe();
    const double initial_difficulty = fixture.session.difficulty();
    const double before_authorize = stats::steady_seconds();
    fixture.authorize("validaddr.worker", std::format("d={}", initial_difficulty));
    const auto window = SessionTestPeek::fixed_share_window(fixture.session);
    CHECK(window.first >= before_authorize);
    CHECK(window.second == 0);

    fixture.conn.sent.clear();
    SessionTestPeek::set_retarget_window(fixture.session, 128);
    fixture.session.maybe_retarget();
    CHECK(fixture.session.difficulty() == doctest::Approx(initial_difficulty));
    CHECK(fixture.conn.sent.empty());
}

TEST_CASE("password difficulty remains fixed after clamping at either configured bound") {
    for (const std::string_view prefix : {"d=", "diff=", "diff_"}) {
        CAPTURE(prefix);
        for (const double requested : {1.0, 1'000.0}) {
            CAPTURE(requested);
            Fixture fixture;
            fixture.pool.vardiff = true;
            fixture.pool.minimum_difficulty = 10.0;
            fixture.pool.maximum_difficulty = 100.0;
            fixture.subscribe();
            fixture.authorize("validaddr.worker", std::format("{}{}", prefix, requested));
            const double expected = std::clamp(requested, 10.0, 100.0);
            REQUIRE(fixture.session.difficulty() == doctest::Approx(expected));
            const auto difficulty = fixture.conn.by_method("mining.set_difficulty");
            REQUIRE(difficulty.has_value());
            CHECK((*difficulty)["params"][0].get<double>() == doctest::Approx(expected));

            for (const uint64_t shares : {uint64_t{128}, uint64_t{0}}) {
                fixture.conn.sent.clear();
                SessionTestPeek::set_retarget_window(fixture.session, shares);
                fixture.session.maybe_retarget();
                CHECK(fixture.session.difficulty() == doctest::Approx(expected));
                CHECK(fixture.conn.sent.empty());
            }
        }
    }
}

TEST_CASE("fixed reauthorization clamps low password tokens to the reloaded minimum") {
    for (const std::string_view password : {"d=1", "diff=1", "diff_1"}) {
        CAPTURE(password);
        for (const bool vardiff : {false, true}) {
            CAPTURE(vardiff);
            Fixture fixture;
            fixture.pool.vardiff = vardiff;
            fixture.subscribe();
            fixture.authorize("validaddr.worker", "d=64");
            fixture.pool.minimum_difficulty = 200.0;
            fixture.conn.sent.clear();

            fixture.authorize("validaddr.worker", password);

            CHECK(fixture.session.difficulty() == doctest::Approx(200.0));
            const auto difficulty = fixture.conn.by_method("mining.set_difficulty");
            REQUIRE(difficulty.has_value());
            CHECK((*difficulty)["params"][0].get<double>() == doctest::Approx(200.0));
            fixture.conn.sent.clear();
            SessionTestPeek::set_retarget_window(fixture.session, 0);
            fixture.session.maybe_retarget();
            CHECK(fixture.session.difficulty() == doctest::Approx(200.0));
            CHECK(fixture.conn.sent.empty());
        }
    }
}

TEST_CASE("difficulty announcements respect a reloaded minimum before the retarget tick") {
    for (const std::string_view operation : {"tokenless reauthorization",
                                             "malformed reauthorization", "resubscribe",
                                             "set difficulty"}) {
        CAPTURE(operation);
        for (const bool fixed : {false, true}) {
            CAPTURE(fixed);
            Fixture fixture;
            fixture.subscribe();
            fixture.authorize("validaddr.worker", fixed ? "d=64" : "x");
            const double previous_difficulty = fixture.session.difficulty();
            fixture.pool.minimum_difficulty = 200.0;
            fixture.conn.sent.clear();

            if (operation == "tokenless reauthorization")
                fixture.authorize("validaddr.worker", "x");
            else if (operation == "malformed reauthorization")
                fixture.authorize("validaddr.worker", "d=oops");
            else if (operation == "resubscribe")
                fixture.subscribe();
            else
                fixture.session.send_set_difficulty();

            CHECK(fixture.session.difficulty() == doctest::Approx(200.0));
            const auto difficulty = fixture.conn.by_method("mining.set_difficulty");
            REQUIRE(difficulty.has_value());
            CHECK((*difficulty)["params"][0].get<double>() == doctest::Approx(200.0));
            fixture.pool.job = make_fake_job(fixture.curtime, 0x20000000, "207fffff");
            const auto nonce = find_accepted_nonce(
                *fixture.pool.job, util::from_hex(fixture.session.extranonce1_hex()),
                previous_difficulty, true);
            REQUIRE_FALSE(nonce.empty());
            fixture.submit(9, nonce);
            CHECK(fixture.pool.block_found);
            CHECK(fixture.pool.last_share_difficulty ==
                  doctest::Approx(operation == "set difficulty" ? previous_difficulty : 200.0));
        }
    }
}

TEST_CASE("passwords without a valid difficulty leave VarDiff and suggestions enabled") {
    for (const std::string_view password : {"", "x", "d=oops", "d=0", "d=-1", "d=nan",
                                           "diff=inf", "diff_1e9999", "d=64oops"}) {
        CAPTURE(password);
        Fixture fixture;
        fixture.pool.vardiff = true;
        fixture.subscribe();
        fixture.authorize("validaddr.worker", password);
        const double initial_difficulty = fixture.session.difficulty();

        SessionTestPeek::set_retarget_window(fixture.session, 128);
        fixture.session.maybe_retarget();
        CHECK(fixture.session.difficulty() == doctest::Approx(initial_difficulty * 2.0));

        fixture.conn.sent.clear();
        fixture.session.handle_line(
            R"({"id":9,"method":"mining.suggest_difficulty","params":[64]})");
        const auto reply = fixture.conn.by_id(9);
        REQUIRE(reply.has_value());
        CHECK((*reply)["result"].get<bool>());
        CHECK(fixture.session.difficulty() == doctest::Approx(64.0));
        CHECK(fixture.conn.by_method("mining.set_difficulty").has_value());

        SessionTestPeek::set_retarget_window(fixture.session, 0);
        fixture.session.maybe_retarget();
        CHECK(fixture.session.difficulty() == doctest::Approx(32.0));
    }
}

TEST_CASE("authorization without a password leaves VarDiff enabled") {
    Fixture fixture;
    fixture.pool.vardiff = true;
    fixture.subscribe();
    fixture.session.handle_line(
        R"({"id":3,"method":"mining.authorize","params":["validaddr.worker"]})");
    REQUIRE(fixture.session.authorized());
    const double initial_difficulty = fixture.session.difficulty();

    SessionTestPeek::set_retarget_window(fixture.session, 128);
    fixture.session.maybe_retarget();
    CHECK(fixture.session.difficulty() == doctest::Approx(initial_difficulty * 2.0));
}

TEST_CASE("fixed password difficulty acknowledges but ignores later suggestions") {
    Fixture fixture;
    fixture.subscribe();
    fixture.authorize("validaddr.worker", "d=64");
    fixture.conn.sent.clear();

    fixture.session.handle_line(
        R"({"id":9,"method":"mining.suggest_difficulty","params":[128]})");
    const auto reply = fixture.conn.by_id(9);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"].get<bool>());
    CHECK(fixture.session.difficulty() == doctest::Approx(64.0));
    CHECK_FALSE(fixture.conn.by_method("mining.set_difficulty").has_value());
    CHECK_FALSE(fixture.conn.by_method("mining.notify").has_value());
}

TEST_CASE("fixed password difficulty still hands off a block below the share difficulty") {
    constexpr double kFixedDifficulty = 1'000'000.0;
    Fixture fixture;
    fixture.subscribe();
    fixture.authorize("validaddr.worker", "d=1000000");
    fixture.pool.job = make_fake_job(fixture.curtime, 0x20000000, "207fffff");
    const std::string nonce = find_accepted_nonce(
        *fixture.pool.job, util::from_hex(fixture.session.extranonce1_hex()), kFixedDifficulty,
        /*require_block=*/true);
    REQUIRE_FALSE(nonce.empty());

    fixture.submit(9, nonce);
    const auto reply = fixture.conn.by_id(9);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"].get<bool>());
    CHECK(fixture.pool.block_found);
    CHECK(fixture.pool.accepted == 1);
    CHECK(fixture.pool.last_share_difficulty == doctest::Approx(kFixedDifficulty));
    CHECK(fixture.pool.last_share_best < kFixedDifficulty);
}

TEST_CASE("same-address reauthorization updates fixed difficulty and preserves it without a token") {
    Fixture fixture;
    fixture.pool.vardiff = true;
    fixture.subscribe();
    fixture.authorize("validaddr.original", "d=64");
    fixture.conn.sent.clear();
    fixture.authorize("validaddr.updated", "diff=128");
    REQUIRE(fixture.session.difficulty() == doctest::Approx(128.0));
    const auto updated = fixture.conn.by_method("mining.set_difficulty");
    REQUIRE(updated.has_value());
    CHECK((*updated)["params"][0].get<double>() == doctest::Approx(128.0));

    for (const std::string_view password : {"x", "", "d=oops", "d=0", "diff=-5", "diff_inf"}) {
        CAPTURE(password);
        fixture.conn.sent.clear();
        fixture.authorize("validaddr.rebound", password);
        const auto reply = fixture.conn.by_id(3);
        REQUIRE(reply.has_value());
        CHECK((*reply)["result"].get<bool>());
        CHECK(fixture.session.difficulty() == doctest::Approx(128.0));

        fixture.conn.sent.clear();
        SessionTestPeek::set_retarget_window(fixture.session, 0);
        fixture.session.maybe_retarget();
        CHECK(fixture.session.difficulty() == doctest::Approx(128.0));
        CHECK(fixture.conn.sent.empty());
    }
}

TEST_CASE("failed initial authorization cannot enable fixed difficulty") {
    Fixture fixture;
    fixture.pool.vardiff = true;
    fixture.subscribe();
    const double initial_difficulty = fixture.session.difficulty();
    fixture.authorize("badaddr.worker", "d=128");
    const auto refused = fixture.conn.by_id(3);
    REQUIRE(refused.has_value());
    CHECK_FALSE((*refused)["result"].get<bool>());
    CHECK_FALSE(fixture.session.authorized());
    CHECK(fixture.session.difficulty() == doctest::Approx(initial_difficulty));

    fixture.authorize("validaddr.worker");
    SessionTestPeek::set_retarget_window(fixture.session, 128);
    fixture.session.maybe_retarget();
    CHECK(fixture.session.difficulty() == doctest::Approx(initial_difficulty * 2.0));
}

TEST_CASE("refused reauthorization preserves the existing difficulty mode") {
    for (const bool fixed : {false, true}) {
        CAPTURE(fixed);
        Fixture fixture;
        fixture.pool.vardiff = true;
        fixture.subscribe();
        fixture.session.handle_line(
            R"({"id":9,"method":"mining.suggest_difficulty","params":[64]})");
        fixture.authorize("validaddr.worker", fixed ? "d=64" : "x");
        REQUIRE(fixture.session.difficulty() == doctest::Approx(64.0));

        fixture.conn.sent.clear();
        fixture.authorize("othervalidaddr.worker", "d=128");
        const auto refused = fixture.conn.by_id(3);
        REQUIRE(refused.has_value());
        CHECK_FALSE((*refused)["result"].get<bool>());
        CHECK(fixture.session.difficulty() == doctest::Approx(64.0));
        CHECK(fixture.session.address() == "validaddr");

        SessionTestPeek::set_retarget_window(fixture.session, 0);
        fixture.session.maybe_retarget();
        CHECK(fixture.session.difficulty() == doctest::Approx(fixed ? 64.0 : 32.0));
    }
}

TEST_CASE("fixed password difficulty follows live bounds even with global VarDiff disabled") {
    for (const bool vardiff : {false, true}) {
        CAPTURE(vardiff);
        Fixture fixture;
        fixture.pool.vardiff = vardiff;
        fixture.subscribe();
        fixture.authorize("validaddr.worker", "d=64");
        REQUIRE(fixture.session.difficulty() == doctest::Approx(64.0));

        fixture.pool.minimum_difficulty = 100.0;
        fixture.conn.sent.clear();
        SessionTestPeek::set_retarget_window(fixture.session, 0);
        fixture.session.maybe_retarget();
        CHECK(fixture.session.difficulty() == doctest::Approx(100.0));
        const auto raised = fixture.conn.by_method("mining.set_difficulty");
        REQUIRE(raised.has_value());
        CHECK((*raised)["params"][0].get<double>() == doctest::Approx(100.0));

        fixture.pool.minimum_difficulty = 1.0;
        fixture.pool.maximum_difficulty = 32.0;
        fixture.conn.sent.clear();
        SessionTestPeek::set_retarget_window(fixture.session, 128);
        fixture.session.maybe_retarget();
        CHECK(fixture.session.difficulty() == doctest::Approx(32.0));
        const auto lowered = fixture.conn.by_method("mining.set_difficulty");
        REQUIRE(lowered.has_value());
        CHECK((*lowered)["params"][0].get<double>() == doctest::Approx(32.0));

        fixture.pool.maximum_difficulty = 0.0;
        fixture.conn.sent.clear();
        SessionTestPeek::set_retarget_window(fixture.session, 128);
        fixture.session.maybe_retarget();
        CHECK(fixture.session.difficulty() == doctest::Approx(32.0));
        CHECK(fixture.conn.sent.empty());
    }
}

TEST_CASE("fixed share windows allow short bursts and raise only above sixty shares per minute") {
    struct WindowCase {
        double elapsed;
        uint64_t accepted;
        double expected_difficulty;
        uint64_t expected_count;
    };
    for (const auto& window : {WindowCase{10.0, 100, 64.0, 101},
                               WindowCase{60.0, 59, 64.0, 0},
                               WindowCase{120.0, 60, 64.0, 0},
                               WindowCase{60.0, 60, 64.0 * 61.0 / 30.0, 0},
                               WindowCase{120.0, 120, 64.0 * 121.0 / 60.0, 0}}) {
        CAPTURE(window.elapsed);
        CAPTURE(window.accepted);
        Fixture fixture;
        fixture.subscribe();
        fixture.authorize("validaddr.worker", "d=64");
        fixture.conn.sent.clear();
        const double now = SessionTestPeek::set_fixed_share_window(
            fixture.session, window.elapsed, window.accepted);
        const auto before = SessionTestPeek::fixed_share_window(fixture.session);

        SessionTestPeek::evaluate_fixed_share_window(fixture.session, now);

        CHECK(fixture.session.difficulty() == doctest::Approx(window.expected_difficulty));
        const auto after = SessionTestPeek::fixed_share_window(fixture.session);
        CHECK(after.second == window.expected_count);
        CHECK(after.first == (window.elapsed < 60.0 ? before.first : now));
        if (window.expected_difficulty > 64.0) {
            CHECK(SessionTestPeek::fixed_difficulty_floor(fixture.session) ==
                  doctest::Approx(window.expected_difficulty));
            CHECK(fixture.conn.by_method("mining.set_difficulty").has_value());
            CHECK(fixture.conn.by_method("mining.notify").has_value());
        } else {
            CHECK(fixture.conn.sent.empty());
        }
    }
}

TEST_CASE("fixed share rate increases follow block handoff and acknowledgement before new work") {
    constexpr double kInitialDifficulty = 3e-10;
    for (const bool vardiff : {false, true}) {
        CAPTURE(vardiff);
        Fixture fixture{true};
        fixture.pool.vardiff = vardiff;
        fixture.pool.job->set_publication_sequence(1);
        fixture.subscribe();
        fixture.authorize("validaddr.worker", std::format("d={}", kInitialDifficulty));
        const std::string nonce = find_accepted_nonce(
            *fixture.pool.job, util::from_hex(fixture.session.extranonce1_hex()),
            kInitialDifficulty, true);
        REQUIRE_FALSE(nonce.empty());
        fixture.conn.sent.clear();
        SessionTestPeek::set_fixed_share_window(fixture.session, 60.0, 60);
        fixture.pool.block_found_hook = [&] {
            CHECK(fixture.session.difficulty() == kInitialDifficulty);
            CHECK_FALSE(fixture.conn.by_id(9).has_value());
            CHECK(fixture.conn.sent.empty());
        };

        fixture.submit(9, nonce);

        CHECK(fixture.pool.block_found);
        CHECK(fixture.pool.accepted == 1);
        CHECK(fixture.pool.last_share_difficulty == kInitialDifficulty);
        CHECK(fixture.session.difficulty() > kInitialDifficulty);
        CHECK(fixture.session.difficulty() == fixture.pool.job->maximum_share_difficulty());
        REQUIRE(fixture.conn.sent.size() == 3);
        CHECK(fixture.conn.sent[0]["id"].get<double>() == 9.0);
        CHECK(fixture.conn.sent[0]["result"].get<bool>());
        CHECK(fixture.conn.sent[1]["method"].get<std::string>() == "mining.set_difficulty");
        CHECK(fixture.conn.sent[1]["params"][0].get<double>() == fixture.session.difficulty());
        CHECK(fixture.conn.sent[2]["method"].get<std::string>() == "mining.notify");
        CHECK(fixture.conn.sent[2]["params"][8].get<bool>());
        CHECK(SessionTestPeek::fixed_share_window(fixture.session).second == 0);
    }
}

TEST_CASE("rejected submissions do not count toward the fixed share rate") {
    Fixture fixture;
    fixture.subscribe();
    fixture.authorize("validaddr.worker", "d=64");
    fixture.pool.job = make_fake_job(fixture.curtime, 0x20000000, "207fffff");
    const Bytes extranonce1 = util::from_hex(fixture.session.extranonce1_hex());
    const std::string accepted_nonce =
        find_accepted_nonce(*fixture.pool.job, extranonce1, 64.0, true);
    REQUIRE_FALSE(accepted_nonce.empty());
    fixture.submit(9, accepted_nonce);
    REQUIRE(fixture.pool.accepted == 1);

    const Bytes coinbase2 = fixture.pool.job->build_coinbase2(kPayoutScript);
    const std::string ntime = fixture.pool.job->ntime_hex();
    std::string rejected_nonce;
    for (uint32_t nonce = 0; nonce < 512; ++nonce) {
        const std::string nonce_hex = std::format("{:08x}", nonce);
        const auto result = fixture.pool.job->validate_share(
            {coinbase2, extranonce1, "01020304", ntime, nonce_hex,
             util::target_from_difficulty(64.0), std::nullopt, 0,
             static_cast<int64_t>(std::time(nullptr))});
        if (!result && result.error().reason == ShareReject::AboveTarget) {
            rejected_nonce = nonce_hex;
            break;
        }
    }
    REQUIRE_FALSE(rejected_nonce.empty());
    SessionTestPeek::set_fixed_share_window(fixture.session, 60.0, 60);
    const auto window = SessionTestPeek::fixed_share_window(fixture.session);
    fixture.conn.sent.clear();

    fixture.submit(10, accepted_nonce);
    fixture.submit(11, rejected_nonce);
    fixture.submit(12, "oops");
    fixture.session.handle_line(
        R"({"id":13,"method":"mining.submit","params":["w","missing","01020304","00000000","00000000"]})");

    CHECK(fixture.pool.accepted == 1);
    CHECK(fixture.pool.rejected == 4);
    CHECK(SessionTestPeek::fixed_share_window(fixture.session) == window);
    CHECK(fixture.session.difficulty() == doctest::Approx(64.0));
    CHECK_FALSE(fixture.conn.by_method("mining.set_difficulty").has_value());
    CHECK_FALSE(fixture.conn.by_method("mining.notify").has_value());
}

TEST_CASE("reauthorization preserves the fixed rate window and its raised floor") {
    Fixture fixture;
    fixture.subscribe();
    fixture.authorize("validaddr.worker", "d=64");
    const double now = SessionTestPeek::set_fixed_share_window(fixture.session, 60.0, 89);
    SessionTestPeek::evaluate_fixed_share_window(fixture.session, now);
    REQUIRE(fixture.session.difficulty() == doctest::Approx(192.0));
    SessionTestPeek::set_fixed_share_window(fixture.session, 30.0, 17);
    const auto window = SessionTestPeek::fixed_share_window(fixture.session);

    struct AuthorizationCase {
        std::string_view user;
        std::string_view password;
        double expected_difficulty;
        bool accepted;
    };
    for (const auto& authorization : {
             AuthorizationCase{"validaddr.worker", "x", 192.0, true},
             AuthorizationCase{"validaddr.rebound", "d=256", 256.0, true},
             AuthorizationCase{"validaddr.rebound", "d=oops", 256.0, true},
             AuthorizationCase{"validaddr.rebound", "d=1", 192.0, true},
             AuthorizationCase{"othervalidaddr.worker", "d=1", 192.0, false}}) {
        CAPTURE(authorization.user);
        CAPTURE(authorization.password);
        fixture.conn.sent.clear();
        fixture.authorize(std::string(authorization.user), authorization.password);
        const auto reply = fixture.conn.by_id(3);
        REQUIRE(reply.has_value());
        CHECK((*reply)["result"].get<bool>() == authorization.accepted);
        CHECK(fixture.session.difficulty() == doctest::Approx(authorization.expected_difficulty));
        CHECK(SessionTestPeek::fixed_share_window(fixture.session) == window);
        CHECK(SessionTestPeek::fixed_difficulty_floor(fixture.session) == doctest::Approx(192.0));
    }

    fixture.session.handle_line(
        R"({"id":14,"method":"mining.authorize","params":["validaddr.worker"]})");
    CHECK(SessionTestPeek::fixed_share_window(fixture.session) == window);
    fixture.conn.sent.clear();
    const double quiet_now = SessionTestPeek::set_fixed_share_window(fixture.session, 60.0, 0);
    SessionTestPeek::evaluate_fixed_share_window(fixture.session, quiet_now);
    CHECK(fixture.session.difficulty() == doctest::Approx(192.0));
    CHECK(fixture.conn.sent.empty());
}

TEST_CASE("fixed rate increases honor freshly reloaded difficulty bounds") {
    struct BoundsCase {
        double minimum;
        double maximum;
        double expected;
    };
    for (const auto& bounds : {BoundsCase{0.001, 100.0, 100.0},
                               BoundsCase{200.0, 500.0, 200.0},
                               BoundsCase{0.001, 64.0, 64.0}}) {
        CAPTURE(bounds.minimum);
        CAPTURE(bounds.maximum);
        Fixture fixture;
        fixture.subscribe();
        fixture.authorize("validaddr.worker", "d=64");
        fixture.pool.minimum_difficulty = bounds.minimum;
        fixture.pool.maximum_difficulty = bounds.maximum;
        const double now = SessionTestPeek::set_fixed_share_window(fixture.session, 60.0, 60);
        SessionTestPeek::evaluate_fixed_share_window(fixture.session, now);
        CHECK(fixture.session.difficulty() == doctest::Approx(bounds.expected));
    }
}

TEST_CASE("operator maximum can temporarily override a fixed rate floor without erasing it") {
    Fixture fixture;
    fixture.subscribe();
    fixture.authorize("validaddr.worker", "d=64");
    fixture.pool.maximum_difficulty = 100.0;
    const double now = SessionTestPeek::set_fixed_share_window(fixture.session, 60.0, 60);
    SessionTestPeek::evaluate_fixed_share_window(fixture.session, now);
    REQUIRE(fixture.session.difficulty() == doctest::Approx(100.0));

    fixture.pool.maximum_difficulty = 32.0;
    fixture.session.maybe_retarget();
    CHECK(fixture.session.difficulty() == doctest::Approx(32.0));
    CHECK(SessionTestPeek::fixed_difficulty_floor(fixture.session) == doctest::Approx(100.0));
    fixture.authorize("validaddr.worker", "d=1");
    CHECK(fixture.session.difficulty() == doctest::Approx(32.0));

    fixture.pool.maximum_difficulty = 0.0;
    fixture.session.maybe_retarget();
    CHECK(fixture.session.difficulty() == doctest::Approx(100.0));
    fixture.authorize("validaddr.worker", "d=1");
    CHECK(fixture.session.difficulty() == doctest::Approx(100.0));
}

TEST_CASE("fixed rate counters and difficulty scaling saturate without overflow") {
    FakePool pool{static_cast<uint32_t>(std::time(nullptr))};
    pool.job.reset();
    FakeConnection connection;
    Session session{pool, connection, util::from_hex("e06ae06a")};
    session.handle_line(R"({"id":1,"method":"mining.subscribe","params":[]})");
    session.handle_line(
        R"({"id":3,"method":"mining.authorize","params":["validaddr.worker","d=1e308"]})");
    REQUIRE(session.difficulty() == 1e308);
    constexpr uint64_t kMaximumShareCount = std::numeric_limits<uint64_t>::max();
    const double burst_now =
        SessionTestPeek::set_fixed_share_window(session, 10.0, kMaximumShareCount);
    SessionTestPeek::evaluate_fixed_share_window(session, burst_now);
    CHECK(SessionTestPeek::fixed_share_window(session).second == kMaximumShareCount);
    CHECK(session.difficulty() == 1e308);

    const double completed_now =
        SessionTestPeek::set_fixed_share_window(session, 60.0, kMaximumShareCount);
    SessionTestPeek::evaluate_fixed_share_window(session, completed_now);
    CHECK(std::isfinite(session.difficulty()));
    CHECK(session.difficulty() == std::numeric_limits<double>::max());
    CHECK(SessionTestPeek::fixed_share_window(session).second == 0);
}

TEST_CASE("a reconnect starts with a fresh fixed share window and no raised floor") {
    Fixture original;
    original.subscribe();
    original.authorize("validaddr.worker", "d=64");
    const double now = SessionTestPeek::set_fixed_share_window(original.session, 60.0, 89);
    SessionTestPeek::evaluate_fixed_share_window(original.session, now);
    REQUIRE(SessionTestPeek::fixed_difficulty_floor(original.session) == doctest::Approx(192.0));

    Fixture reconnected;
    reconnected.subscribe();
    reconnected.authorize("validaddr.worker", "d=1");
    CHECK(reconnected.session.difficulty() == doctest::Approx(1.0));
    CHECK(SessionTestPeek::fixed_difficulty_floor(reconnected.session) == 0.0);
    const auto window = SessionTestPeek::fixed_share_window(reconnected.session);
    CHECK(window.first >= now);
    CHECK(window.second == 0);
}

TEST_CASE("accepted shares leave ordinary VarDiff sessions outside the fixed rate safeguard") {
    Fixture fixture;
    fixture.pool.vardiff = true;
    fixture.subscribe();
    fixture.authorize("validaddr.worker");
    const double initial_difficulty = fixture.session.difficulty();
    const std::string nonce = find_accepted_nonce(
        *fixture.pool.job, util::from_hex(fixture.session.extranonce1_hex()), initial_difficulty);
    REQUIRE_FALSE(nonce.empty());
    fixture.conn.sent.clear();
    fixture.submit(9, nonce);

    CHECK(fixture.pool.accepted == 1);
    CHECK(fixture.session.difficulty() == doctest::Approx(initial_difficulty));
    CHECK(SessionTestPeek::fixed_share_window(fixture.session).first == 0.0);
    CHECK(SessionTestPeek::fixed_share_window(fixture.session).second == 0);
    CHECK(SessionTestPeek::fixed_difficulty_floor(fixture.session) == 0.0);
    CHECK(fixture.conn.sent.size() == 1);
    SessionTestPeek::set_retarget_window(fixture.session, 128);
    fixture.session.maybe_retarget();
    CHECK(fixture.session.difficulty() == doctest::Approx(initial_difficulty * 2.0));
}

TEST_CASE("network difficulty overrides a higher minimum for every password difficulty token") {
    for (const std::string_view password : {"d=1000", "diff=1000", "diff_1000"}) {
        CAPTURE(password);
        Fixture fixture;
        fixture.pool.job = make_fake_job(fixture.curtime, 0x20000000, "1d00ffff");
        fixture.pool.minimum_difficulty = 200.0;
        fixture.pool.maximum_difficulty = 500.0;
        fixture.subscribe();
        fixture.authorize("validaddr.worker", password);

        CHECK(fixture.session.difficulty() == 1.0);
        const auto difficulty = fixture.conn.by_method("mining.set_difficulty");
        REQUIRE(difficulty.has_value());
        CHECK((*difficulty)["params"][0].get<double>() == 1.0);
        CHECK(fixture.conn.by_method("mining.notify").has_value());
        fixture.authorize("validaddr.worker", "d=0.5");
        CHECK(fixture.session.difficulty() == 1.0);
    }
}

TEST_CASE("initial and suggested difficulty stay within the network ceiling") {
    const uint32_t curtime = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool{curtime};
    pool.job = make_fake_job(curtime, 0x20000000, "1d00ffff");
    pool.initial_difficulty = 64.0;
    pool.minimum_difficulty = 200.0;
    pool.maximum_difficulty = 500.0;
    FakeConnection connection;
    Session session{pool, connection, util::from_hex("e06ae06a")};
    CHECK(session.difficulty() == 1.0);

    session.handle_line(R"({"id":1,"method":"mining.subscribe","params":[]})");
    session.handle_line(R"({"id":9,"method":"mining.suggest_difficulty","params":[1000]})");
    const auto reply = connection.by_id(9);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"].get<bool>());
    CHECK(session.difficulty() == 1.0);
    session.send_set_difficulty();
    const auto difficulty = connection.by_method("mining.set_difficulty");
    REQUIRE(difficulty.has_value());
    CHECK((*difficulty)["params"][0].get<double>() == 1.0);
}

TEST_CASE("a configured maximum below network difficulty still takes precedence") {
    Fixture fixture;
    fixture.pool.job = make_fake_job(fixture.curtime, 0x20000000, "1d00ffff");
    fixture.pool.minimum_difficulty = 0.001;
    fixture.pool.maximum_difficulty = 0.5;
    fixture.subscribe();
    fixture.authorize("validaddr.worker", "d=1000");

    CHECK(fixture.session.difficulty() == 0.5);
    const auto difficulty = fixture.conn.by_method("mining.set_difficulty");
    REQUIRE(difficulty.has_value());
    CHECK((*difficulty)["params"][0].get<double>() == 0.5);
}

TEST_CASE("new jobs lower excessive difficulty before notifying fixed and ordinary miners") {
    for (const bool fixed : {false, true}) {
        CAPTURE(fixed);
        for (const bool vardiff : {false, true}) {
            CAPTURE(vardiff);
            Fixture fixture;
            fixture.pool.vardiff = vardiff;
            fixture.subscribe();
            fixture.session.handle_line(
                R"({"id":9,"method":"mining.suggest_difficulty","params":[64]})");
            fixture.authorize("validaddr.worker", fixed ? "d=64" : "x");
            REQUIRE(fixture.session.difficulty() == 64.0);
            if (fixed) {
                const double now = SessionTestPeek::set_fixed_share_window(
                    fixture.session, 60.0, 89);
                SessionTestPeek::evaluate_fixed_share_window(fixture.session, now);
                REQUIRE(SessionTestPeek::fixed_difficulty_floor(fixture.session) == 192.0);
            }
            fixture.pool.minimum_difficulty = 200.0;
            fixture.pool.job = make_fake_job(fixture.curtime, 0x20000000, "1d00ffff");
            fixture.pool.job->set_publication_sequence(2);
            fixture.conn.sent.clear();

            fixture.session.send_notify(*fixture.pool.job, true);

            CHECK(fixture.session.difficulty() == 1.0);
            REQUIRE(fixture.conn.sent.size() == 2);
            CHECK(fixture.conn.sent[0]["method"].get<std::string>() == "mining.set_difficulty");
            CHECK(fixture.conn.sent[0]["params"][0].get<double>() == 1.0);
            CHECK(fixture.conn.sent[1]["method"].get<std::string>() == "mining.notify");
            CHECK(fixture.conn.sent[1]["params"][6].get<std::string>() == "1d00ffff");
            fixture.conn.sent.clear();
            for (const uint64_t shares : {uint64_t{128}, uint64_t{0}, uint64_t{128}}) {
                SessionTestPeek::set_retarget_window(fixture.session, shares);
                fixture.session.maybe_retarget();
                CHECK(fixture.session.difficulty() == 1.0);
                CHECK(fixture.conn.sent.empty());
            }
        }
    }
}

TEST_CASE("a broadcast uses its own network ceiling rather than the pool current job") {
    Fixture fixture;
    fixture.subscribe();
    fixture.authorize("validaddr.worker", "d=64");
    const auto incoming = make_fake_job(fixture.curtime, 0x20000000, "1d00ffff");
    incoming->set_publication_sequence(2);
    fixture.conn.sent.clear();

    fixture.session.send_notify(*incoming, true);

    CHECK(fixture.session.difficulty() == 1.0);
    REQUIRE(fixture.conn.sent.size() == 2);
    CHECK(fixture.conn.sent[0]["method"].get<std::string>() == "mining.set_difficulty");
    CHECK(fixture.conn.sent[0]["params"][0].get<double>() == 1.0);
    CHECK(fixture.conn.sent[1]["params"][6].get<std::string>() == "1d00ffff");
    CHECK(fixture.pool.job->maximum_share_difficulty() > 64.0);
    fixture.conn.sent.clear();
    fixture.session.maybe_retarget();
    CHECK(fixture.session.difficulty() == 1.0);
    CHECK(fixture.conn.sent.empty());
}

TEST_CASE("fixed difficulty restores its request or rate floor when network difficulty rises") {
    for (const bool raised_floor : {false, true}) {
        CAPTURE(raised_floor);
        Fixture fixture;
        fixture.subscribe();
        fixture.authorize("validaddr.worker", "d=64");
        if (raised_floor) {
            const double now = SessionTestPeek::set_fixed_share_window(fixture.session, 60.0, 89);
            SessionTestPeek::evaluate_fixed_share_window(fixture.session, now);
        }
        const double expected = raised_floor ? 192.0 : 64.0;
        REQUIRE(fixture.session.difficulty() == expected);
        fixture.pool.job = make_fake_job(fixture.curtime, 0x20000000, "1d00ffff");
        fixture.pool.job->set_publication_sequence(2);
        fixture.session.send_notify(*fixture.pool.job, true);
        REQUIRE(fixture.session.difficulty() == 1.0);
        CHECK(SessionTestPeek::fixed_difficulty_floor(fixture.session) ==
              (raised_floor ? 192.0 : 0.0));
        fixture.conn.sent.clear();
        fixture.session.maybe_retarget();
        CHECK(fixture.session.difficulty() == 1.0);
        CHECK(fixture.conn.sent.empty());

        fixture.pool.job = make_fake_job(fixture.curtime);
        fixture.pool.job->set_publication_sequence(3);
        fixture.session.send_notify(*fixture.pool.job, true);

        CHECK(fixture.session.difficulty() == expected);
        REQUIRE(fixture.conn.sent.size() == 2);
        CHECK(fixture.conn.sent[0]["method"].get<std::string>() == "mining.set_difficulty");
        CHECK(fixture.conn.sent[0]["params"][0].get<double>() == expected);
        CHECK(fixture.conn.sent[1]["method"].get<std::string>() == "mining.notify");
        fixture.conn.sent.clear();
        fixture.session.maybe_retarget();
        CHECK(fixture.session.difficulty() == expected);
        CHECK(fixture.conn.sent.empty());
    }
}

TEST_CASE("announced network ceilings preserve the exact block target") {
    for (const std::string_view bits : {"1d00ffff", "1d00fffe", "1a123456", "207fffff",
                                        "01010000"}) {
        CAPTURE(bits);
        Fixture fixture;
        fixture.pool.job = make_fake_job(fixture.curtime, 0x20000000, bits);
        fixture.subscribe();
        fixture.authorize("validaddr.worker", "d=1e100");
        const auto difficulty = fixture.conn.by_method("mining.set_difficulty");
        REQUIRE(difficulty.has_value());
        const double announced = (*difficulty)["params"][0].get<double>();
        CHECK(announced == fixture.pool.job->maximum_share_difficulty());
        CHECK(util::target_from_difficulty(announced) >= fixture.pool.job->network_target());
    }
}

TEST_CASE("fixed rate increases cannot exceed the network difficulty") {
    Fixture fixture;
    fixture.pool.job = make_fake_job(fixture.curtime, 0x20000000, "1d00ffff");
    fixture.subscribe();
    fixture.authorize("validaddr.worker", "d=0.75");
    const double now = SessionTestPeek::set_fixed_share_window(fixture.session, 60.0, 89);
    SessionTestPeek::evaluate_fixed_share_window(fixture.session, now);
    REQUIRE(fixture.session.difficulty() == 1.0);
    CHECK(SessionTestPeek::fixed_difficulty_floor(fixture.session) == 1.0);
    fixture.pool.minimum_difficulty = 200.0;
    fixture.conn.sent.clear();

    const double next = SessionTestPeek::set_fixed_share_window(fixture.session, 60.0, 89);
    SessionTestPeek::evaluate_fixed_share_window(fixture.session, next);

    CHECK(fixture.session.difficulty() == 1.0);
    CHECK(fixture.conn.sent.empty());
    fixture.session.maybe_retarget();
    CHECK(fixture.session.difficulty() == 1.0);
    CHECK(fixture.conn.sent.empty());
    fixture.authorize("validaddr.worker", "d=1000");
    CHECK(fixture.session.difficulty() == 1.0);
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
    CHECK(f.session.protocol_errors() == 1);
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
    CHECK(f.session.protocol_errors() == 1);
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

TEST_CASE("control requests have a capped burst and refill once per second") {
    Fixture fixture;
    const auto start = SessionTestPeek::control_time(fixture.session);
    for (size_t request = 0; request < SessionTestPeek::control_burst(); ++request)
        REQUIRE(SessionTestPeek::allow_control(fixture.session, start));
    CHECK_FALSE(fixture.session.should_close());
    CHECK(SessionTestPeek::allow_control(fixture.session, start + std::chrono::seconds(1)));
    CHECK(SessionTestPeek::allow_control(fixture.session, start + std::chrono::seconds(2)));

    const auto later = start + std::chrono::hours(1);
    for (size_t request = 0; request < SessionTestPeek::control_burst(); ++request)
        REQUIRE(SessionTestPeek::allow_control(fixture.session, later));
    CHECK_FALSE(SessionTestPeek::allow_control(fixture.session, later));
    CHECK(fixture.session.should_close());
    CHECK_FALSE(SessionTestPeek::allow_control(fixture.session, later + std::chrono::hours(1)));
}

TEST_CASE("successful repeated authorization exhausts only that connection's control budget") {
    Fixture fixture;
    SessionTestPeek::freeze_control_refill(fixture.session);
    fixture.subscribe();
    fixture.authorize("validaddr.original");
    for (size_t request = 2; request < SessionTestPeek::control_burst(); ++request) {
        fixture.authorize("validaddr.rebound");
        CHECK_FALSE(fixture.session.should_close());
    }
    CHECK(fixture.session.protocol_errors() == 0);
    CHECK(*fixture.session.worker() == "rebound");
    const size_t attached_before = fixture.pool.attached.size();
    fixture.conn.sent.clear();
    fixture.authorize("validaddr.denied");
    CHECK(fixture.session.should_close());
    CHECK(fixture.conn.sent.empty());
    CHECK(fixture.pool.attached.size() == attached_before);
    CHECK(*fixture.session.address() == "validaddr");
    CHECK(*fixture.session.worker() == "rebound");

    // Connections behind one NAT are independent even though the fake peer is identical.
    Fixture other;
    other.subscribe();
    other.authorize("validaddr.other");
    CHECK(other.session.authorized());
    CHECK_FALSE(other.session.should_close());
}

TEST_CASE("shares bypass an empty control budget without replenishing it") {
    Fixture fixture{true};
    SessionTestPeek::freeze_control_refill(fixture.session);
    fixture.subscribe();
    fixture.authorize("validaddr.worker");
    fixture.session.handle_line(
        R"({"id":9,"method":"mining.authorize","params":["othervalidaddr.worker"]})");
    REQUIRE(fixture.session.protocol_errors() == 1);
    for (size_t request = 3; request < SessionTestPeek::control_burst(); ++request)
        fixture.session.handle_line(R"({"id":10,"method":"mining.ping","params":[]})");
    CHECK_FALSE(fixture.session.should_close());

    const std::string nonce = find_accepted_nonce(
        *fixture.pool.job, util::from_hex("e06ae06a"), fixture.session.difficulty(), true);
    REQUIRE_FALSE(nonce.empty());
    fixture.submit(11, nonce);
    REQUIRE(fixture.conn.by_id(11).has_value());
    CHECK((*fixture.conn.by_id(11))["result"].get<bool>());
    CHECK(fixture.pool.block_found);
    CHECK(fixture.session.protocol_errors() == 0);
    for (size_t request = 0; request < SessionTestPeek::control_burst(); ++request)
        fixture.submit(12, nonce);
    CHECK_FALSE(fixture.session.should_close());

    fixture.authorize("validaddr.worker");
    CHECK(fixture.session.should_close());
}

TEST_CASE("a closing session still submits a block from the current read") {
    Fixture fixture{true};
    SessionTestPeek::freeze_control_refill(fixture.session);
    fixture.subscribe();
    fixture.authorize("validaddr.worker");
    const std::string block_nonce = find_accepted_nonce(
        *fixture.pool.job, util::from_hex("e06ae06a"), fixture.session.difficulty(), true);
    REQUIRE_FALSE(block_nonce.empty());

    for (size_t request = 2; request <= SessionTestPeek::control_burst(); ++request)
        fixture.session.handle_line(R"({"id":10,"method":"mining.ping","params":[]})");
    REQUIRE(fixture.session.should_close());

    fixture.conn.sent.clear();
    fixture.authorize("validaddr.ignored");
    CHECK(fixture.conn.sent.empty());
    CHECK(*fixture.session.worker() == "worker");

    fixture.submit(11, block_nonce);
    REQUIRE(fixture.conn.by_id(11).has_value());
    CHECK((*fixture.conn.by_id(11))["result"].get<bool>());
    CHECK(fixture.pool.block_found);
    CHECK(fixture.pool.accepted == 1);
    CHECK(fixture.session.should_close());
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
    Fixture f{true};
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

TEST_CASE("omitted and zero version bits deduplicate when the header is unchanged") {
    Fixture f{true};
    SUBCASE("without version rolling") {}
    SUBCASE("with version rolling") { f.configure_mask("1fffe000"); }
    f.subscribe();
    f.authorize("validaddr.w");
    const std::string nonce = find_accepted_nonce(
        *f.pool.job, util::from_hex("e06ae06a"), f.pool.start_difficulty(), true);
    REQUIRE_FALSE(nonce.empty());

    f.submit(6, nonce);
    REQUIRE(f.pool.block_found);
    REQUIRE(f.pool.accepted == 1);
    f.submit(7, nonce, "00000000");
    const auto duplicate = f.conn.by_id(7);
    REQUIRE(duplicate.has_value());
    CHECK((*duplicate)["error"][0].get<double>() == 22);
    CHECK(f.pool.accepted == 1);
}

TEST_CASE("mask renegotiation does not make the same header new work") {
    Fixture f{true};
    f.configure_mask("1fffe000");
    f.subscribe();
    f.authorize("validaddr.w");
    const std::string nonce = find_accepted_nonce(
        *f.pool.job, util::from_hex("e06ae06a"), f.pool.start_difficulty(), true);
    REQUIRE_FALSE(nonce.empty());

    f.submit(6, nonce, "00000000");
    REQUIRE(f.pool.accepted == 1);
    f.configure_mask("0fffe000");
    REQUIRE(f.session.version_mask() == 0x0fffe000u);
    f.submit(7, nonce, "0");
    const auto duplicate = f.conn.by_id(7);
    REQUIRE(duplicate.has_value());
    CHECK((*duplicate)["error"][0].get<double>() == 22);
    CHECK(f.pool.accepted == 1);
}

TEST_CASE("omitted version bits preserve rolled bits from the template") {
    Fixture f{true};
    f.pool.job = make_fake_job(f.curtime, 0x20002000, "207fffff");
    f.configure_mask("1fffe000");
    f.subscribe();
    f.authorize("validaddr.w");
    const std::string nonce = find_accepted_nonce(
        *f.pool.job, util::from_hex("e06ae06a"), f.pool.start_difficulty(), true);
    REQUIRE_FALSE(nonce.empty());

    f.submit(6, nonce);
    REQUIRE(f.pool.accepted == 1);
    f.submit(7, nonce, "00002000");
    const auto duplicate = f.conn.by_id(7);
    REQUIRE(duplicate.has_value());
    CHECK((*duplicate)["error"][0].get<double>() == 22);

    f.submit(8, nonce, "00000000");
    const auto different_header = f.conn.by_id(8);
    REQUIRE(different_header.has_value());
    CHECK(((*different_header)["error"].is_null() ||
           (*different_header)["error"][0].get<double>() != 22));
}

TEST_CASE("invalid version bits cannot reserve the key of a valid block") {
    Fixture f{true};
    SUBCASE("without version rolling") {}
    SUBCASE("with version rolling") { f.configure_mask("1fffe000"); }
    f.subscribe();
    f.authorize("validaddr.w");
    const std::string nonce = find_accepted_nonce(
        *f.pool.job, util::from_hex("e06ae06a"), f.pool.start_difficulty(), true);
    REQUIRE_FALSE(nonce.empty());

    for (const std::string_view bits : {"nothex", "00000001", "20000000"})
        f.submit(6, nonce, bits);
    CHECK(f.pool.accepted == 0);
    CHECK(f.pool.rejected == 3);
    f.submit(7, nonce);
    CHECK(f.pool.accepted == 1);
    CHECK(f.pool.block_found);
}

TEST_CASE("an empty nonce cannot reserve the key of a zero nonce") {
    Fixture f;
    f.subscribe();
    f.authorize("validaddr.w");
    f.submit(6, "");
    f.submit(7, "00000000");
    const auto valid_nonce = f.conn.by_id(7);
    REQUIRE(valid_nonce.has_value());
    CHECK(((*valid_nonce)["error"].is_null() ||
           (*valid_nonce)["error"][0].get<double>() != 22));
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
    const double high = start_diff * 2.0;

    std::string baseline_nonce;
    std::string in_flight_nonce;
    std::string harder_nonce;
    const Bytes coinbase2 = f.pool.job->build_coinbase2(kPayoutScript);
    for (uint32_t n = 0;
         n < 4096 && (baseline_nonce.empty() || in_flight_nonce.empty() || harder_nonce.empty());
         ++n) {
        const std::string nonce_hex = std::format("{:08x}", n);
        ShareInput in;
        in.coinbase2 = coinbase2;
        in.extranonce1 = enonce1;
        in.extranonce2_hex = "01020304";
        in.ntime_hex = f.pool.job->ntime_hex();
        in.nonce_hex = nonce_hex;
        in.share_target = util::target_from_difficulty(start_diff);
        in.now_unix = static_cast<int64_t>(std::time(nullptr));
        const auto result = f.pool.job->validate_share(in);
        if (!result)
            continue;
        if (baseline_nonce.empty())
            baseline_nonce = nonce_hex;
        else if (in_flight_nonce.empty() && result->difficulty < high)
            in_flight_nonce = nonce_hex;
        else if (harder_nonce.empty() && result->difficulty >= high)
            harder_nonce = nonce_hex;
    }
    REQUIRE_FALSE(baseline_nonce.empty());
    REQUIRE_FALSE(in_flight_nonce.empty());
    REQUIRE_FALSE(harder_nonce.empty());

    const auto submit = [&](int id, const std::string& nonce) {
        f.conn.sent.clear();
        f.session.handle_line(std::format(
            R"({{"id":{},"method":"mining.submit","params":["w","job1","01020304","{}","{}"]}})", id,
            f.pool.job->ntime_hex(), nonce));
    };

    // Baseline: no pending change -> credited at the current difficulty.
    submit(10, baseline_nonce);
    CHECK((*f.conn.by_id(10))["result"].get<bool>() == true);
    CHECK(f.pool.last_share_difficulty == start_diff);

    // An in-flight share retains its old difficulty until the next job.
    f.session.handle_line(
        std::format(R"({{"id":11,"method":"mining.suggest_difficulty","params":[{}]}})", high));
    CHECK(f.session.difficulty() == high); // advertised value changed immediately
    submit(12, in_flight_nonce);
    CHECK((*f.conn.by_id(12))["result"].get<bool>() == true); // accepted, not "above target"
    CHECK(f.pool.last_share_difficulty == start_diff); // credited the OLD difficulty

    // The next job ends the grace window; subsequent shares credit the NEW difficulty.
    f.session.send_notify(*f.pool.job, /*clean=*/true);
    submit(13, harder_nonce);
    CHECK((*f.conn.by_id(13))["result"].get<bool>() == true);
    CHECK(f.pool.last_share_difficulty == high); // credited the NEW difficulty
}

TEST_CASE("difficulty-grace crediting: LOWER direction and the meets-the-harder-target branch") {
    // Exercise both credit branches while a downward change is pending.
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

    // Both difficulties stay above the 256-bit target overflow floor (~2.3e-10).
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
    REQUIRE(session.difficulty() == lo); // advertised immediately

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
    CHECK(pool.last_share_difficulty == hi);

    // A share that only meets the easier NEW target credits at lo.
    submit(22, easy);
    CHECK((*conn.by_id(22))["result"].get<bool>() == true);
    CHECK(pool.last_share_difficulty == lo);
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

TEST_CASE("vardiff_next has no implicit ceiling when maximum difficulty is zero") {
    const Config config = Config::from_string(
        R"({"minimum_difficulty":10000000000000,"maximum_difficulty":0})");
    CHECK(vardiff_next(1e12, 1000, 12, 0.001, 0) == doctest::Approx(2e12));
    CHECK(vardiff_next(1e13, 12, 12, config.minimum_difficulty,
                      config.maximum_difficulty) == doctest::Approx(1e13));
    CHECK(vardiff_next(1e13, 0, 12, config.minimum_difficulty,
                      config.maximum_difficulty) == doctest::Approx(1e13));
    CHECK(vardiff_next(1e13, 1000, 12, config.minimum_difficulty,
                      config.maximum_difficulty) == doctest::Approx(2e13));
}

TEST_CASE("vardiff_next saturates without overflowing double") {
    constexpr double kMaximum = std::numeric_limits<double>::max();
    CHECK(vardiff_next(kMaximum / 2.0, 1000, 12, 0.001, 0) == kMaximum);
    CHECK(vardiff_next(kMaximum * 0.75, 1000, 12, 0.001, 0) == kMaximum);
    CHECK(vardiff_next(kMaximum, 1000, 12, 0.001, 0) == kMaximum);
    CHECK(vardiff_next(kMaximum, 0, 12, 0.001, 0) == kMaximum / 2.0);
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
    CHECK(f.session.difficulty() == doctest::Approx(256.0));
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

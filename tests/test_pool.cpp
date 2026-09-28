#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <semaphore>
#include <sstream>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "api/snapshot.hpp"
#include "bitcoin/rpc_client.hpp"
#include "bitcoin/work_source.hpp"
#include "bitcoin/work_source_rpc.hpp"
#include "core/config.hpp"
#include "core/errors.hpp"
#include "core/logging.hpp"
#include "gbt_fixture.hpp"
#include "mining/work_identity.hpp"
#include "pool/pool.hpp"
#include "work_generation_fixture.hpp"
#include "stats/poolstatus.hpp"
#include "sv2/connection.hpp"
#include "util/hex.hpp"
#include "util/endian.hpp"
#include "util/sha256.hpp"

using namespace erikslund;

namespace {
// A Pool with an unconnected RPC client -- next_job_id() does no I/O (same pattern as
// test_http.cpp). The submit thread idles and stops cleanly on destruction.
bool is_lower_hex(const std::string& s) {
    return !s.empty() && s.find_first_not_of("0123456789abcdef") == std::string::npos;
}

class InconclusiveRpc final : public bitcoin::RpcClient {
public:
    InconclusiveRpc() : RpcClient("http://127.0.0.1:1", "user", "pass") {}
    std::atomic<int> calls{0};

protected:
    std::string post_one(const Resolved&, const std::string&, long, long* http_status) override {
        calls.fetch_add(1, std::memory_order_relaxed);
        if (http_status)
            *http_status = 200;
        return R"({"result":"inconclusive","error":null,"id":1})";
    }
};

class UnreachableRpc final : public bitcoin::RpcClient {
public:
    UnreachableRpc() : RpcClient("http://127.0.0.1:1", "user", "pass") {}
    std::atomic<int> calls{0};

protected:
    std::string post_one(const Resolved&, const std::string&, long, long*) override {
        calls.fetch_add(1, std::memory_order_relaxed);
        throw RpcConnectionError("transport error: connection reset");
    }
};

class RecoveringRpc final : public bitcoin::RpcClient {
public:
    RecoveringRpc() : RpcClient("http://127.0.0.1:1", "user", "pass") {}
    std::atomic<int> calls{0};

protected:
    std::string post_one(const Resolved&, const std::string&, long, long* http_status) override {
        const int call = calls.fetch_add(1, std::memory_order_relaxed);
        if (http_status)
            *http_status = 200;
        if (call == 0)
            return R"({"result":"inconclusive","error":null,"id":1})";
        return R"({"result":null,"error":null,"id":1})";
    }
};

class RejectingRpc final : public bitcoin::RpcClient {
public:
    RejectingRpc() : RpcClient("http://127.0.0.1:1", "user", "pass") {}

protected:
    std::string post_one(const Resolved&, const std::string&, long, long* http_status) override {
        if (http_status)
            *http_status = 200;
        return R"({"result":"bad-cb-amount","error":null,"id":1})";
    }
};

class DuplicateRpc final : public bitcoin::RpcClient {
public:
    DuplicateRpc() : RpcClient("http://127.0.0.1:1", "user", "pass") {}
    std::atomic<int> calls{0};

protected:
    std::string post_one(const Resolved&, const std::string&, long, long* http_status) override {
        calls.fetch_add(1, std::memory_order_relaxed);
        if (http_status)
            *http_status = 200;
        return R"({"result":"duplicate","error":null,"id":1})";
    }
};

class LostReplyThenDuplicateRpc final : public bitcoin::RpcClient {
public:
    LostReplyThenDuplicateRpc() : RpcClient("http://127.0.0.1:1", "user", "pass") {}
    int calls = 0;

protected:
    std::string post_one(const Resolved&, const std::string&, long, long* http_status) override {
        if (++calls == 1)
            throw RpcConnectionError("transport error: connection reset");
        if (http_status)
            *http_status = 200;
        return R"({"result":"duplicate","error":null,"id":1})";
    }
};

class DuplicateInconclusiveRpc final : public bitcoin::RpcClient {
public:
    DuplicateInconclusiveRpc() : RpcClient("http://127.0.0.1:1", "user", "pass") {}

protected:
    std::string post_one(const Resolved&, const std::string&, long, long* http_status) override {
        if (http_status)
            *http_status = 200;
        return R"({"result":"duplicate-inconclusive","error":null,"id":1})";
    }
};

class TestConnection final : public stratum::Connection, public sv2::Connection {
public:
    void send_line(std::string_view) override {}
    void send_bytes(ByteView) override {}
    std::string peer() const override { return "test"; }
};

class RecordingPublicationClient final : public mining::Client {
public:
    void publish_job(const stratum::Job&, bool) override {
        calls.fetch_add(1, std::memory_order_relaxed);
        called.release();
    }
    void maybe_retarget() override {}
    mining::ClientStats stats(bool) const override { return {}; }
    bool ever_authorized() const override { return false; }
    int protocol_errors() const override { return 0; }
    bool should_close() const override { return false; }

    std::atomic<int> calls{0};
    std::binary_semaphore called{0};
};

class BlockingPublicationClient final : public mining::Client {
public:
    void publish_job(const stratum::Job& job, bool clean) override {
        const int call = calls.fetch_add(1, std::memory_order_relaxed);
        {
            const std::scoped_lock lock(records_mutex);
            job_ids.push_back(job.job_id());
            clean_flags.push_back(clean);
        }
        if (call == 0) {
            entered.release();
            proceed.acquire();
        }
        completed.release();
    }
    void maybe_retarget() override {}
    mining::ClientStats stats(bool) const override { return {}; }
    bool ever_authorized() const override { return false; }
    int protocol_errors() const override { return 0; }
    bool should_close() const override { return false; }

    std::atomic<int> calls{0};
    std::binary_semaphore entered{0};
    std::binary_semaphore proceed{0};
    std::counting_semaphore<16> completed{0};
    std::mutex records_mutex;
    std::vector<std::string> job_ids;
    std::vector<bool> clean_flags;
};

bitcoin::BlockTemplate refresh_template() {
    test::gbt_json data = test::gbt_json::object_t{};
    data["height"] = 170;
    data["version"] = 0x20000000;
    data["curtime"] = 1700000000;
    data["bits"] = std::string("1d00ffff");
    data["coinbasevalue"] = 5000000000LL;
    data["previousblockhash"] = std::string(64, 'a');
    data["transactions"] = test::gbt_json::array_t{};
    return test::from_template(data);
}

std::shared_ptr<stratum::Job> publication_job(std::string id, uint64_t sequence) {
    const Bytes tag{'/', 'e', 'p', '/'};
    auto job = std::make_shared<stratum::Job>(
        std::move(id), refresh_template(), tag, 4, 8, 1);
    job->set_publication_sequence(sequence);
    return job;
}

Config sv2_publication_config() {
    Config config;
    config.sv2_plaintext_ports = {13334};
    return config;
}

class FlappingWorkSource final : public bitcoin::WorkSource {
public:
    std::atomic<bool> failing{false};
    std::atomic<size_t> failures{0};
    std::atomic<size_t> template_successes{0};
    std::atomic<size_t> tip_successes{0};
    std::atomic<size_t> submissions{0};

    bitcoin::ChainInfo detect_chain() override { return {.chain = "regtest", .blocks = 169}; }

    std::string get_tip() override {
        tip_successes.fetch_add(1, std::memory_order_relaxed);
        return std::string(64, failing.load(std::memory_order_acquire) ? 'b' : 'a');
    }

    bitcoin::BlockTemplate fetch_template() override {
        if (failing.load(std::memory_order_acquire)) {
            failures.fetch_add(1, std::memory_order_relaxed);
            throw RpcConnectionError(
                R"({"code":-9,"message":"Bitcoin Core is not connected!"})");
        }
        template_successes.fetch_add(1, std::memory_order_relaxed);
        return block_template_;
    }

    bitcoin::HeaderFacts fetch_header(const std::string&) override { return {}; }

    std::optional<std::string> submit_block_hex(const std::string&) override {
        submissions.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

private:
    const bitcoin::BlockTemplate block_template_ = refresh_template();
};

class TemplateOutageWorkSource final : public bitcoin::WorkSource {
public:
    std::atomic<bool> templates_available{true};
    std::atomic<char> tip{'a'};
    std::atomic<size_t> tip_probes{0};
    std::atomic<size_t> template_failures{0};
    size_t header_fetches = 0;

    bitcoin::ChainInfo detect_chain() override { return {.chain = "regtest", .blocks = 169}; }

    std::string get_tip() override {
        tip_probes.fetch_add(1, std::memory_order_relaxed);
        return std::string(64, tip.load());
    }

    bitcoin::BlockTemplate fetch_template() override {
        if (!templates_available.load()) {
            template_failures.fetch_add(1, std::memory_order_relaxed);
            throw RpcConnectionError("template generation unavailable");
        }
        const char current_tip = tip.load();
        auto result = refresh_template();
        result.height += current_tip - 'a';
        result.previousblockhash = std::string(64, current_tip);
        return result;
    }

    bitcoin::HeaderFacts fetch_header(const std::string& hash) override {
        ++header_fetches;
        const char current_tip = tip.load();
        return {.height = 169 + current_tip - 'a',
                .confirmations = hash == std::string(64, current_tip) ? 1 : -1,
                .bits_hex = "1d00ffff",
                .mediantime = 1700000000};
    }

    std::optional<std::string> submit_block_hex(const std::string&) override {
        return std::nullopt;
    }
};

// Serves templates on a settable chain and reports a settable standing for the block the pool asks
// about, so tests can tell a node that abandoned the current parent from one still catching up.
class RollbackWorkSource final : public bitcoin::WorkSource {
public:
    std::atomic<bitcoin::BlockStanding> standing{bitcoin::BlockStanding::Pending};
    std::atomic<size_t> template_fetches{0};
    std::atomic<size_t> standing_checks{0};

    void set_chain(char parent, int64_t height) {
        const std::scoped_lock lock(mutex_);
        parent_ = parent;
        height_ = height;
    }

    std::string checked_block() {
        const std::scoped_lock lock(mutex_);
        return checked_block_;
    }

    bitcoin::ChainInfo detect_chain() override { return {.chain = "regtest", .blocks = 170}; }

    std::string get_tip() override {
        const std::scoped_lock lock(mutex_);
        return std::string(64, parent_);
    }

    bitcoin::BlockTemplate fetch_template() override {
        template_fetches.fetch_add(1, std::memory_order_relaxed);
        auto result = refresh_template();
        const std::scoped_lock lock(mutex_);
        result.height = height_;
        result.previousblockhash = std::string(64, parent_);
        return result;
    }

    bitcoin::HeaderFacts fetch_header(const std::string&) override { return {}; }

    bitcoin::BlockStanding block_standing(const std::string& block_hash) override {
        {
            const std::scoped_lock lock(mutex_);
            checked_block_ = block_hash;
        }
        standing_checks.fetch_add(1, std::memory_order_relaxed);
        return standing.load();
    }

    std::optional<std::string> submit_block_hex(const std::string&) override {
        return std::nullopt;
    }

private:
    std::mutex mutex_;
    char parent_ = 'b';
    int64_t height_ = 171;
    std::string checked_block_;
};

constexpr int64_t kRecoveredBlockHeight = 500;
constexpr std::chrono::seconds kSynchronizationTimeout{5};
constexpr std::string_view kRecoveredBlockHeaderHex =
    "01000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    "29ab5f49"
    "ffff001d"
    "1dac2b7c";

class BlockingFastblockHeaderSource final : public bitcoin::WorkSource {
public:
    std::atomic<char> tip{'a'};
    std::atomic<size_t> tip_probes{0};
    bool fail_header = false;
    std::promise<void> header_entered;
    const std::shared_future<void> header_started = header_entered.get_future().share();
    std::binary_semaphore continue_header{0};

    bitcoin::ChainInfo detect_chain() override { return {.chain = "regtest", .blocks = 169}; }

    std::string get_tip() override {
        const char current_tip = tip.load();
        tip_probes.fetch_add(1, std::memory_order_relaxed);
        // Hold the early probe until fastblock enters its header lookup.
        if (current_tip == 'b' &&
            header_started.wait_for(kSynchronizationTimeout) != std::future_status::ready)
            throw RpcConnectionError("header lookup did not start");
        return std::string(64, current_tip);
    }

    bitcoin::BlockTemplate fetch_template() override {
        const char current_tip = tip.load();
        auto result = refresh_template();
        result.height += current_tip - 'a';
        result.previousblockhash = std::string(64, current_tip);
        return result;
    }

    bitcoin::HeaderFacts fetch_header(const std::string&) override {
        header_entered.set_value();
        continue_header.acquire();
        if (fail_header)
            throw RpcConnectionError("header lookup failed");
        return {.height = 170, .confirmations = 1,
                .bits_hex = "1d00ffff", .mediantime = 1700000000};
    }

    std::optional<std::string> submit_block_hex(const std::string&) override {
        return std::nullopt;
    }
};

struct RecoveredBlockFixture {
    std::filesystem::path stats_directory;
    std::filesystem::path spool_path;
    std::string block_hash;
};

RecoveredBlockFixture write_recovered_block(std::string_view test_directory,
                                            std::string filename_hash = {}) {
    namespace fs = std::filesystem;
    const fs::path stats_directory = fs::temp_directory_path() / test_directory;
    fs::remove_all(stats_directory);
    fs::create_directories(stats_directory / "blocks");

    const Bytes header = util::from_hex(kRecoveredBlockHeaderHex);
    const std::string block_hash = util::to_hex_reversed(util::sha256d(header));
    if (filename_hash.empty())
        filename_hash = block_hash;
    const fs::path spool_path =
        stats_directory / "blocks" /
        std::format("{}_{}.hex", kRecoveredBlockHeight, filename_hash);
    { std::ofstream(spool_path, std::ios::binary) << kRecoveredBlockHeaderHex << '\n'; }
    return {stats_directory, spool_path, block_hash};
}

struct RecoveredChainState {
    std::string candidate_hash;
    int64_t candidate_height = kRecoveredBlockHeight;
    std::string tip_hash;
    int64_t tip_height = kRecoveredBlockHeight;
    int64_t candidate_confirmations = 1;
    bool fail_tip_lookup = false;
};

class RecoveredBlockWorkSource final : public bitcoin::WorkSource {
public:
    explicit RecoveredBlockWorkSource(RecoveredChainState state) : state_(std::move(state)) {}

    bitcoin::ChainInfo detect_chain() override { return {.chain = "regtest", .blocks = 0}; }

    std::string get_tip() override {
        tip_lookups.fetch_add(1, std::memory_order_relaxed);
        if (state_.fail_tip_lookup)
            throw RpcConnectionError("tip lookup failed");
        return state_.tip_hash;
    }

    bitcoin::BlockTemplate fetch_template() override { return refresh_template(); }

    bitcoin::HeaderFacts fetch_header(const std::string& block_hash) override {
        if (block_hash == state_.tip_hash) {
            tip_header_lookups.fetch_add(1, std::memory_order_relaxed);
            return {.height = state_.tip_height,
                    .confirmations = 1,
                    .bits_hex = {},
                    .mediantime = 0};
        }
        if (block_hash == state_.candidate_hash) {
            candidate_header_lookups.fetch_add(1, std::memory_order_relaxed);
            return {.height = state_.candidate_height,
                    .confirmations = state_.candidate_confirmations,
                    .bits_hex = {},
                    .mediantime = 0};
        }
        throw RpcError("unexpected block header lookup");
    }

    std::optional<std::string> submit_block_hex(const std::string&) override {
        submissions.fetch_add(1, std::memory_order_relaxed);
        return "inconclusive";
    }

    std::atomic<size_t> submissions{0};
    std::atomic<size_t> tip_lookups{0};
    std::atomic<size_t> tip_header_lookups{0};
    std::atomic<size_t> candidate_header_lookups{0};

private:
    const RecoveredChainState state_;
};

enum class RecoveryPause { Submission, TipLookup };

class BlockingRecoveryWorkSource final : public bitcoin::WorkSource {
public:
    BlockingRecoveryWorkSource(std::string candidate_hash, RecoveryPause pause)
        : candidate_hash_(std::move(candidate_hash)), pause_(pause) {}

    bitcoin::ChainInfo detect_chain() override { return {.chain = "regtest", .blocks = 0}; }

    std::string get_tip() override {
        tip_lookups.fetch_add(1, std::memory_order_relaxed);
        if (pause_ == RecoveryPause::TipLookup) {
            recovery_paused.release();
            continue_recovery.acquire();
        }
        return candidate_hash_;
    }

    bitcoin::BlockTemplate fetch_template() override { return refresh_template(); }

    bitcoin::HeaderFacts fetch_header(const std::string&) override { return {}; }

    std::optional<std::string> submit_block_hex(const std::string& block_hex) override {
        if (block_hex == kRecoveredBlockHeaderHex) {
            const size_t attempt = recovered_submissions.fetch_add(1, std::memory_order_relaxed);
            if (pause_ == RecoveryPause::Submission && attempt == 0) {
                recovery_paused.release();
                continue_recovery.acquire();
            }
            return "inconclusive";
        }

        live_submissions.fetch_add(1, std::memory_order_relaxed);
        live_submission_started.release();
        return std::nullopt;
    }

    std::atomic<size_t> recovered_submissions{0};
    std::atomic<size_t> live_submissions{0};
    std::atomic<size_t> tip_lookups{0};
    std::binary_semaphore recovery_paused{0};
    std::binary_semaphore continue_recovery{0};
    std::binary_semaphore live_submission_started{0};

private:
    const std::string candidate_hash_;
    const RecoveryPause pause_;
};

class BlockingLiveWorkSource final : public bitcoin::WorkSource {
public:
    bitcoin::ChainInfo detect_chain() override { return {.chain = "regtest", .blocks = 0}; }
    std::string get_tip() override { return {}; }
    bitcoin::BlockTemplate fetch_template() override { return refresh_template(); }
    bitcoin::HeaderFacts fetch_header(const std::string&) override { return {}; }

    std::optional<std::string> submit_block_hex(const std::string&) override {
        const size_t attempt = submissions.fetch_add(1, std::memory_order_relaxed);
        if (attempt == 0) {
            submission_started.release();
            continue_submission.acquire();
        }
        if (attempt == 0 && first_attempt_inconclusive)
            return "inconclusive";
        if (fail_submission)
            throw RpcConnectionError("transport error: connection reset");
        return response;
    }

    std::atomic<size_t> submissions{0};
    std::binary_semaphore submission_started{0};
    std::binary_semaphore continue_submission{0};
    std::optional<std::string> response = "inconclusive";
    bool first_attempt_inconclusive = false;
    bool fail_submission = false;
};

class BlockingRetryWorkSource final : public bitcoin::WorkSource {
public:
    bitcoin::ChainInfo detect_chain() override { return {.chain = "regtest", .blocks = 0}; }
    std::string get_tip() override { return {}; }
    bitcoin::BlockTemplate fetch_template() override { return refresh_template(); }
    bitcoin::HeaderFacts fetch_header(const std::string&) override { return {}; }

    std::optional<std::string> submit_block_hex(const std::string&) override {
        const size_t attempt = submissions.fetch_add(1, std::memory_order_relaxed);
        if (attempt == 0)
            return "inconclusive";
        if (attempt == 1) {
            retry_started.release();
            continue_retry.acquire();
            return retry_response;
        }
        fresh_submission_started.release();
        return std::nullopt;
    }

    std::atomic<size_t> submissions{0};
    std::binary_semaphore retry_started{0};
    std::binary_semaphore continue_retry{0};
    std::binary_semaphore fresh_submission_started{0};
    std::optional<std::string> retry_response = std::nullopt;
};

template <typename Predicate>
bool wait_until(Predicate&& predicate) {
    for (int attempt = 0; attempt < 1000; ++attempt) {
        if (predicate())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return predicate();
}

size_t occurrence_count(std::string_view text, std::string_view needle) {
    size_t count = 0;
    for (size_t offset = 0; (offset = text.find(needle, offset)) != std::string_view::npos;
         offset += needle.size())
        ++count;
    return count;
}
} // namespace

TEST_CASE("validate_address resolves locally, without any bitcoind RPC") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc); // refused -> any RPC call throws
    Pool pool(config, rpc_source, test::kWorkGeneration);

    // network_ defaults to Regtest. A valid regtest address yields a P2WPKH script with no RPC --
    // the dead endpoint above would make any RPC-based validation fail.
    const auto ok = pool.validate_address("bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf");
    REQUIRE(ok.has_value());
    CHECK(ok->size() == 22); // OP_0 <0x14> + 20-byte witness program

    // Rejected locally (no RPC, no throw): garbage, a wrong-network (mainnet) address, and empty.
    CHECK_FALSE(pool.validate_address("notanaddress").has_value());
    CHECK_FALSE(pool.validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").has_value());
    CHECK_FALSE(pool.validate_address("").has_value());
}

TEST_CASE("Pool applies reloadable mining settings without replacing startup state") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);
    CHECK(pool.snapshot().config_generation == 0);
    CHECK_FALSE(pool.snapshot().last_reload_rejected);

    pool.note_config_reload_rejected();
    CHECK(pool.snapshot().config_generation == 0);
    CHECK(pool.snapshot().last_reload_rejected);

    Config replacement = config;
    replacement.initial_difficulty = 128.0;
    replacement.minimum_difficulty = 4.0;
    replacement.maximum_difficulty = 8192.0;
    replacement.variable_difficulty = false;
    replacement.vardiff_target_shares_per_minute = 24.0;
    replacement.vardiff_retarget_seconds = 20;
    replacement.version_rolling_mask = 0x00002000u;
    pool.reload_config(replacement.runtime_config());

    const auto runtime = pool.runtime_config();
    CHECK(runtime->initial_difficulty == doctest::Approx(128.0));
    CHECK(runtime->minimum_difficulty == doctest::Approx(4.0));
    CHECK(runtime->maximum_difficulty == doctest::Approx(8192.0));
    CHECK_FALSE(runtime->variable_difficulty);
    CHECK(runtime->vardiff_target_shares_per_minute == doctest::Approx(24.0));
    CHECK(runtime->vardiff_retarget_seconds == 20);
    CHECK(pool.version_mask() == config.version_rolling_mask);
    CHECK(pool.snapshot().config_generation == 1);
    CHECK_FALSE(pool.snapshot().last_reload_rejected);
}

TEST_CASE("SV2 readiness expires without waiting for another handshake") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);

    pool.set_sv2_authenticated_state(true, 1);
    const api::PoolSnapshot expired = pool.snapshot();
    REQUIRE(expired.sv2_authenticated_ready.has_value());
    CHECK_FALSE(*expired.sv2_authenticated_ready);
    CHECK(expired.sv2_certificate_expiry_timestamp == 1);

    pool.set_sv2_authenticated_state(true,
                                     std::numeric_limits<uint32_t>::max());
    const api::PoolSnapshot valid = pool.snapshot();
    REQUIRE(valid.sv2_authenticated_ready.has_value());
    CHECK(*valid.sv2_authenticated_ready);
}

TEST_CASE("next_job_id is 16 hex: a stable per-process prefix + a monotonic counter") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);

    const std::string a = pool.next_job_id();
    const std::string b = pool.next_job_id();
    const std::string c = pool.next_job_id();

    for (const std::string& id : {a, b, c}) {
        CHECK(id.size() == 16); // 8-hex prefix + 8-hex counter (e.g. "1eccbf7200000001")
        CHECK(is_lower_hex(id));
    }
    // The high half is the per-process prefix -- identical across calls.
    CHECK(a.substr(0, 8) == b.substr(0, 8));
    CHECK(b.substr(0, 8) == c.substr(0, 8));
    // The low half is a monotonic counter starting at 1.
    CHECK(a.substr(8) == "00000001");
    CHECK(b.substr(8) == "00000002");
    CHECK(c.substr(8) == "00000003");
    CHECK(a != b);
    CHECK(b != c);
}

TEST_CASE("next_job_id: independent pools advance independent counters") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool p1(config, rpc_source, test::kWorkGeneration);
    Pool p2(config, rpc_source, test::kWorkGeneration);

    // Wire IDs retain independent counters; the coinbase generation separates actual work.
    const std::string id1 = p1.next_job_id();
    const std::string id2 = p2.next_job_id();
    CHECK(id1.size() == 16);
    CHECK(id2.size() == 16);
    CHECK(id1.substr(8) == "00000001"); // independent counters, both from 1
    CHECK(id2.substr(8) == "00000001");
}

TEST_CASE("replica extranonce1 prefixes partition otherwise identical session counters") {
    Config first_config;
    first_config.extranonce1_size = 6;
    first_config.extranonce1_prefix = {0x00, 0x01};
    Config second_config = first_config;
    second_config.extranonce1_prefix = {0x00, 0x02};
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    const auto before_start = static_cast<uint32_t>(std::time(nullptr));
    Pool first(first_config, rpc_source, test::kWorkGeneration);
    Pool second(second_config, rpc_source, test::kWorkGeneration);

    const auto first_session = first.add_client(std::make_shared<TestConnection>());
    const auto second_session = second.add_client(std::make_shared<TestConnection>());
    const auto next_first_session = first.add_client(std::make_shared<TestConnection>());

    const auto after_start = static_cast<uint32_t>(std::time(nullptr));
    const auto first_counter =
        static_cast<uint32_t>(std::stoul(first_session->extranonce1_hex().substr(4), nullptr, 16));
    const auto second_counter =
        static_cast<uint32_t>(std::stoul(second_session->extranonce1_hex().substr(4), nullptr, 16));
    const auto next_first_counter = static_cast<uint32_t>(
        std::stoul(next_first_session->extranonce1_hex().substr(4), nullptr, 16));

    CHECK(first_session->extranonce1_hex().starts_with("0001"));
    CHECK(second_session->extranonce1_hex().starts_with("0002"));
    CHECK(first_counter >= before_start + 1);
    CHECK(first_counter <= after_start + 1);
    CHECK(second_counter >= before_start + 1);
    CHECK(second_counter <= after_start + 1);
    CHECK(next_first_counter == first_counter + 1);
}

TEST_CASE("fastblock follows successive tips during a template outage and recovers") {
    Config config;
    config.poll_interval = 0.001;
    config.work_rebroadcast_seconds = 3600;
    TemplateOutageWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    std::jthread worker([&pool](const std::stop_token& stop) { pool.refresh_work(stop); });
    REQUIRE(wait_until([&] { return source.tip_probes.load() != 0; }));
    REQUIRE(pool.current_job()->mines_on(std::string(64, 'a')));

    source.templates_available.store(false);
    source.tip.store('b');
    REQUIRE(wait_until([&] { return source.template_failures.load() != 0; }));
    pool.on_zmq_block(std::string(64, 'b'));
    CHECK(pool.current_job()->mines_on(std::string(64, 'b')));

    source.tip.store('c');
    pool.on_zmq_block(std::string(64, 'c'));
    const auto latest_fastblock = pool.current_job();
    CHECK(latest_fastblock->mines_on(std::string(64, 'c')));
    CHECK(latest_fastblock->height() == 172);
    CHECK(source.header_fetches == 2);

    pool.on_zmq_block(std::string(64, 'c'));
    CHECK(pool.current_job() == latest_fastblock);
    CHECK(source.header_fetches == 2);

    source.templates_available.store(true);
    REQUIRE(wait_until([&] { return pool.current_job() != latest_fastblock; }));
    CHECK(pool.current_job()->mines_on(std::string(64, 'c')));
    const auto recovered = pool.current_job();
    pool.on_zmq_block(std::string(64, 'c'));
    CHECK(pool.current_job() == recovered);
    CHECK(source.header_fetches == 2);
}

TEST_CASE("ZMQ wakes template refresh before a blocked fastblock header lookup finishes") {
    Config config;
    config.poll_interval = 3600;
    config.work_rebroadcast_seconds = 3600;
    BlockingFastblockHeaderSource source;
    SUBCASE("header lookup succeeds") {}
    SUBCASE("header lookup fails") { source.fail_header = true; }
    Pool pool(config, source, test::kWorkGeneration);
    std::jthread worker([&pool](const std::stop_token& stop) { pool.refresh_work(stop); });
    REQUIRE(wait_until([&] { return pool.current_job() != nullptr; }));
    pool.notify_new_block();
    REQUIRE(wait_until([&] { return source.tip_probes.load() != 0; }));

    source.tip.store('b');
    std::jthread notification([&] { pool.on_zmq_block(std::string(64, 'b')); });
    const bool header_blocked =
        source.header_started.wait_for(kSynchronizationTimeout) == std::future_status::ready;
    const bool refreshed_while_blocked = header_blocked && wait_until([&] {
        return pool.current_job()->mines_on(std::string(64, 'b'));
    });
    const auto full_job = pool.current_job();

    source.continue_header.release();
    notification.join();
    worker.request_stop();
    worker.join();

    CHECK(header_blocked);
    REQUIRE(refreshed_while_blocked);
    CHECK(pool.current_job() == full_job);
    CHECK(full_job->height() == 171);
}

TEST_CASE("a lower template replaces the current work once bitcoind abandoned its parent") {
    Config config;
    config.poll_interval = 0.001;
    config.work_rebroadcast_seconds = 3600;
    RollbackWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    pool.set_connector_ready(true);
    std::jthread worker([&pool](const std::stop_token& stop) { pool.refresh_work(stop); });
    REQUIRE(wait_until([&] {
        const auto job = pool.current_job();
        return job && job->height() == 171;
    }));

    // invalidateblock on the current parent: the node now builds at 170 on 'a'.
    source.standing.store(bitcoin::BlockStanding::Abandoned);
    source.set_chain('a', 170);
    REQUIRE(wait_until([&] { return pool.current_job()->mines_on(std::string(64, 'a')); }));
    CHECK(pool.current_job()->height() == 170);
    CHECK(source.checked_block() == std::string(64, 'b'));
    CHECK(pool.ready());
}

TEST_CASE("a lower template from a lagging bitcoind keeps the work, paces refetches, and "
          "reports the stall") {
    Config config;
    config.poll_interval = 0.001;
    config.work_rebroadcast_seconds = 1;
    RollbackWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    pool.set_connector_ready(true);
    std::jthread worker([&pool](const std::stop_token& stop) { pool.refresh_work(stop); });
    REQUIRE(wait_until([&] {
        const auto job = pool.current_job();
        return job && job->height() == 171;
    }));
    REQUIRE(pool.ready());

    // The node reports a lower tip but has not abandoned 'b' (standing stays Pending).
    source.set_chain('a', 170);
    REQUIRE(wait_until([&] { return source.standing_checks.load() != 0; }));
    const size_t fetches_at_refusal = source.template_fetches.load();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    // One template per rebroadcast interval, not one per 1 ms poll.
    CHECK(source.template_fetches.load() - fetches_at_refusal <= 1);
    CHECK(pool.current_job()->mines_on(std::string(64, 'b')));
    CHECK(pool.ready());

    // Refused for longer than two rebroadcast intervals: readiness reports the stall.
    const auto deadline = std::chrono::steady_clock::now() + kSynchronizationTimeout;
    while (pool.ready() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CHECK_FALSE(pool.ready());
    CHECK_FALSE(pool.snapshot().ready);
    CHECK(pool.current_job()->mines_on(std::string(64, 'b')));

    // The node catches up past the current work.
    source.set_chain('c', 172);
    REQUIRE(wait_until([&] { return pool.current_job()->mines_on(std::string(64, 'c')); }));
    CHECK(pool.ready());
}

TEST_CASE("refresh_work logs one warning and one recovery per outage") {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "ep-refresh-log-test";
    const fs::path path = dir / "pool.log";
    fs::remove_all(dir);

    const log::Level previous_level = log::level();
    log::set_level(log::Level::Info);
    const bool log_opened = log::set_log_file(path.string());

    Config config;
    config.poll_interval = 0.001;
    config.work_rebroadcast_seconds = 3600;
    FlappingWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    std::jthread worker([&pool](const std::stop_token& stop) { pool.refresh_work(stop); });

    const bool template_ready = wait_until([&pool] { return pool.current_job() != nullptr; });
    const auto original_job = pool.current_job();
    source.failing.store(true, std::memory_order_release);
    const bool outage_retried =
        wait_until([&source] { return source.failures.load() >= 20; });
    const auto outage_snapshot = pool.snapshot();
    const auto retained_job = pool.current_job();
    const size_t recovery_start = source.template_successes.load();
    source.failing.store(false, std::memory_order_release);
    const bool recovered =
        wait_until([&source, recovery_start] {
            return source.template_successes.load() > recovery_start;
        });

    worker.request_stop();
    worker.join();
    log::set_log_file("");
    log::set_level(previous_level);

    std::ifstream input(path);
    std::stringstream buffer;
    buffer << input.rdbuf();
    const std::string contents = buffer.str();

    CHECK(log_opened);
    CHECK(template_ready);
    CHECK(outage_retried);
    CHECK(recovered);
    CHECK(source.tip_successes.load() != 0);
    CHECK_FALSE(outage_snapshot.generator_ready);
    REQUIRE(original_job != nullptr);
    REQUIRE(retained_job != nullptr);
    CHECK(retained_job->job_id() == original_job->job_id());
    CHECK(occurrence_count(contents, "Work refresh failed") == 1);
    CHECK(occurrence_count(contents, "Work refresh recovered") == 1);
    CHECK(pool.snapshot().generator_ready);

    fs::remove_all(dir);
}

TEST_CASE("resubmit_spooled_blocks leaves the block on disk when bitcoind is unreachable") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_resubmit_test";
    fs::remove_all(stats);
    fs::create_directories(stats / "blocks");
    const fs::path block = stats / "blocks" / "500_abc.hex";
    { std::ofstream(block, std::ios::binary) << "00112233\n"; }

    Config config;
    config.stats_directory = stats.string();
    UnreachableRpc rpc;
    bitcoin::RpcWorkSource rpc_source(rpc);
    {
        Pool pool(config, rpc_source, test::kWorkGeneration);
        pool.resubmit_spooled_blocks();
        REQUIRE(wait_until([&] { return rpc.calls.load(std::memory_order_relaxed) == 1; }));
    }

    // Shutdown drops the in-memory retry, but the original remains durable for the next run.
    CHECK(fs::exists(block));
    CHECK_FALSE(fs::exists(block.string() + ".submitted"));
    CHECK_FALSE(fs::exists(block.string() + ".rejected"));

    fs::remove_all(stats);
}

TEST_CASE("resubmit_spooled_blocks leaves an inconclusive submission available for retry") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_resubmit_inconclusive_test";
    fs::remove_all(stats);
    fs::create_directories(stats / "blocks");
    const fs::path block = stats / "blocks" / "500_abc.hex";
    { std::ofstream(block, std::ios::binary) << "00112233\n"; }

    Config config;
    config.stats_directory = stats.string();
    InconclusiveRpc rpc;
    bitcoin::RpcWorkSource rpc_source(rpc);
    {
        Pool pool(config, rpc_source, test::kWorkGeneration);
        pool.resubmit_spooled_blocks();
        REQUIRE(wait_until([&] { return rpc.calls.load(std::memory_order_relaxed) == 1; }));
    }

    CHECK(fs::exists(block));
    CHECK_FALSE(fs::exists(block.string() + ".submitted"));
    CHECK_FALSE(fs::exists(block.string() + ".rejected"));

    fs::remove_all(stats);
}

TEST_CASE("resubmit_spooled_blocks is a no-op when there is no blocks directory") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_resubmit_empty";
    fs::remove_all(stats);

    Config config;
    config.stats_directory = stats.string();
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);
    CHECK_NOTHROW(pool.resubmit_spooled_blocks()); // nothing spooled -> nothing to do
}

// Persistent per-worker stats: the registry survives disconnect (entries are not tied to a live
// session) and restart (recover_user_stats re-seeds from users/ files, decaying by file age).
// These drive a Pool through its share hooks + snapshot; no bitcoind I/O is needed.

namespace {
// Find an address's worker rows in a snapshot (sorted by name for stable assertions).
std::vector<api::WorkerSnapshot> workers_of(const api::PoolSnapshot& s, const std::string& addr) {
    std::vector<api::WorkerSnapshot> out;
    for (const auto& w : s.workers)
        if (w.address == addr)
            out.push_back(w);
    std::sort(out.begin(), out.end(),
              [](const auto& a, const auto& b) { return a.worker < b.worker; });
    return out;
}
const char* kAddr = "bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf";
} // namespace

namespace erikslund::stats {
struct WorkerAccountingTestPeek {
    static std::unique_lock<std::mutex> lock_row(WorkerAccounting& accounting) {
        return std::unique_lock(accounting.mutex_);
    }
};
} // namespace erikslund::stats

namespace erikslund {
struct PoolTestPeek {
    static auto make_job(Pool& pool, bitcoin::BlockTemplate block_template) {
        return pool.make_job(std::move(block_template), false);
    }
    static void seed_extranonce_counter(Pool& pool, uint64_t value) {
        pool.extranonce1_counter_.store(value);
    }
    static void exhaust_job_counter(Pool& pool) {
        pool.job_counter_.store(std::numeric_limits<uint64_t>::max());
    }
    static void prune(Pool& pool, int64_t now) { pool.prune_user_stats(now); }
    static bool submit(Pool& pool, const std::string& hash, const std::string& address) {
        const Pool::PendingBlock block{1, hash, "00", address, "w"};
        return pool.submit_block(block);
    }
    static void add_client(Pool& pool,
                           const std::shared_ptr<mining::Client>& session,
                           bool publish_asynchronously) {
        const std::scoped_lock lock(pool.mutex_);
        pool.clients_.push_back(
            std::make_shared<Pool::ConnectedClient>(
                Pool::ConnectedClient{std::make_shared<TestConnection>(),
                                      session, publish_asynchronously}));
    }
    static void publish(Pool& pool, const std::shared_ptr<const stratum::Job>& job) {
        (void)pool.broadcast_job(job, true);
    }
    static void enqueue(Pool& pool,
                        const std::shared_ptr<mining::Client>& session,
                        const std::shared_ptr<const stratum::Job>& job,
                        bool clean) {
        std::shared_ptr<Pool::ConnectedClient> client;
        {
            const std::scoped_lock lock(pool.mutex_);
            const auto found =
                std::ranges::find_if(pool.clients_, [&](const auto& candidate) {
                    return candidate->session == session;
                });
            if (found != pool.clients_.end())
                client = *found;
        }
        if (client)
            pool.enqueue_publication(client, job, clean);
    }
    static bool publication_worker_started(const Pool& pool) {
        return pool.publication_thread_.joinable();
    }
    static size_t pending_live_submissions(Pool& pool) {
        const std::scoped_lock lock(pool.submit_mutex_);
        return pool.submit_queue_.size();
    }
    static std::stop_token live_submission_stop_token(Pool& pool) {
        return pool.submit_thread_.get_stop_token();
    }
    static std::stop_token recovery_submission_stop_token(Pool& pool) {
        return pool.recovery_thread_.get_stop_token();
    }
    static void stop_workers(Pool& pool) { pool.stop_workers(); }
    static void stop_recovery_worker(Pool& pool) {
        pool.recovery_thread_.request_stop();
        pool.recovery_cv_.notify_all();
        pool.recovery_thread_.join();
    }
    static size_t pending_recovered_submissions(Pool& pool) {
        const std::scoped_lock lock(pool.recovery_mutex_);
        return pool.recovery_queue_.size();
    }
    static void retry_recovered_submissions_now(Pool& pool) {
        {
            const std::scoped_lock lock(pool.recovery_mutex_);
            for (auto& submission : pool.recovery_queue_)
                submission.retry_after = {};
        }
        pool.recovery_cv_.notify_all();
    }
    static void delay_recovered_submissions(Pool& pool) {
        const std::scoped_lock lock(pool.recovery_mutex_);
        for (auto& submission : pool.recovery_queue_)
            submission.retry_after = std::chrono::steady_clock::now() + std::chrono::hours(1);
    }
    static bool submit_recovered(Pool& pool, const std::filesystem::path& path) {
        const Pool::PendingBlock block{0, path.filename().string(), "00112233", "", ""};
        return pool.submit_recovered_block(block, path);
    }
};
} // namespace erikslund

namespace {
bool wait_for_first_recovered_submission(Pool& pool, RecoveredBlockWorkSource& source) {
    pool.resubmit_spooled_blocks();
    return wait_until(
               [&] { return source.submissions.load(std::memory_order_relaxed) == 1; }) &&
           wait_until([&] { return PoolTestPeek::pending_recovered_submissions(pool) == 1; });
}

void enqueue_live_block(Pool& pool, char hash_digit) {
    const Bytes tag{'/', 't', '/'};
    stratum::Job job("live", refresh_template(), tag, 4, 4, 1);
    stratum::ShareResult result;
    result.difficulty = 1.0;
    result.is_block = true;
    result.legacy_coinbase = {0};
    result.block_hash_chars.fill(hash_digit);
    pool.on_block_found(kAddr, "worker", job, result);
}

std::filesystem::path live_spool_path(const std::filesystem::path& stats, char hash_digit) {
    return stats / "blocks" / (std::to_string(refresh_template().height) + "_" +
                                std::string(64, hash_digit) + ".hex");
}
} // namespace

TEST_CASE("a blocked recovered submission does not delay a live block") {
    namespace fs = std::filesystem;
    const auto fixture = write_recovered_block("ep_recovery_submit_isolation_test");
    BlockingRecoveryWorkSource source(fixture.block_hash, RecoveryPause::Submission);
    Config config;
    config.stats_directory = fixture.stats_directory.string();

    {
        Pool pool(config, source, test::kWorkGeneration);
        pool.resubmit_spooled_blocks();
        const bool recovery_paused =
            source.recovery_paused.try_acquire_for(kSynchronizationTimeout);
        bool live_started = false;
        if (recovery_paused) {
            enqueue_live_block(pool, 'd');
            live_started =
                source.live_submission_started.try_acquire_for(kSynchronizationTimeout);
        }
        source.continue_recovery.release();

        REQUIRE(recovery_paused);
        CHECK(live_started);
        CHECK(source.live_submissions.load(std::memory_order_relaxed) == 1);
        CHECK(wait_until([&] { return pool.blocks_found() == 1; }));
    }

    fs::remove_all(fixture.stats_directory);
}

TEST_CASE("a blocked recovered tip lookup does not delay a live block") {
    namespace fs = std::filesystem;
    const auto fixture = write_recovered_block("ep_recovery_tip_isolation_test");
    BlockingRecoveryWorkSource source(fixture.block_hash, RecoveryPause::TipLookup);
    Config config;
    config.stats_directory = fixture.stats_directory.string();

    {
        Pool pool(config, source, test::kWorkGeneration);
        pool.resubmit_spooled_blocks();
        REQUIRE(wait_until([&] {
            return source.recovered_submissions.load(std::memory_order_relaxed) == 1;
        }));
        REQUIRE(wait_until(
            [&] { return PoolTestPeek::pending_recovered_submissions(pool) == 1; }));
        PoolTestPeek::retry_recovered_submissions_now(pool);

        const bool recovery_paused =
            source.recovery_paused.try_acquire_for(kSynchronizationTimeout);
        bool live_started = false;
        if (recovery_paused) {
            enqueue_live_block(pool, 'e');
            live_started =
                source.live_submission_started.try_acquire_for(kSynchronizationTimeout);
        }
        source.continue_recovery.release();

        REQUIRE(recovery_paused);
        CHECK(live_started);
        CHECK(source.live_submissions.load(std::memory_order_relaxed) == 1);
        CHECK(wait_until([&] { return pool.blocks_found() == 1; }));
        CHECK(source.recovered_submissions.load(std::memory_order_relaxed) == 1);
    }

    fs::remove_all(fixture.stats_directory);
}

TEST_CASE("an inconclusive live block submission is retried") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_live_submission_retry_test";
    fs::remove_all(stats);
    Config config;
    config.stats_directory = stats.string();
    RecoveringRpc rpc;
    bitcoin::RpcWorkSource source(rpc);

    {
        Pool pool(config, source, test::kWorkGeneration);
        enqueue_live_block(pool, 'c');
        REQUIRE(wait_until([&] { return rpc.calls.load(std::memory_order_relaxed) == 1; }));
        REQUIRE(wait_until([&] { return PoolTestPeek::pending_recovered_submissions(pool) == 1; }));
        CHECK(PoolTestPeek::pending_live_submissions(pool) == 0);

        PoolTestPeek::retry_recovered_submissions_now(pool);
        REQUIRE(wait_until([&] { return rpc.calls.load(std::memory_order_relaxed) == 2; }));
        REQUIRE(wait_until([&] { return pool.blocks_found() == 1; }));
        CHECK(PoolTestPeek::pending_live_submissions(pool) == 0);
        CHECK(PoolTestPeek::pending_recovered_submissions(pool) == 0);

        CHECK(fs::exists(live_spool_path(stats, 'c')));
    }

    fs::remove_all(stats);
}

TEST_CASE("a blocked live retry does not delay a new candidate or lose block credit") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_live_retry_isolation_test";
    fs::remove_all(stats);
    Config config;
    config.stats_directory = stats.string();
    BlockingRetryWorkSource source;

    {
        Pool pool(config, source, test::kWorkGeneration);
        enqueue_live_block(pool, 'a');
        if (wait_until([&] { return PoolTestPeek::pending_recovered_submissions(pool) == 1; }))
            PoolTestPeek::retry_recovered_submissions_now(pool);
        const bool retry_started = source.retry_started.try_acquire_for(kSynchronizationTimeout);
        bool fresh_started = false;
        if (retry_started) {
            enqueue_live_block(pool, 'b');
            fresh_started =
                source.fresh_submission_started.try_acquire_for(kSynchronizationTimeout);
        }
        source.continue_retry.release();

        REQUIRE(retry_started);
        CHECK(fresh_started);
        REQUIRE(wait_until([&] { return pool.blocks_found() == 2; }));
        CHECK(source.submissions.load(std::memory_order_relaxed) == 3);
        CHECK(pool.snapshot().blocks_by_address.at(kAddr) == 2);
        CHECK(fs::exists(live_spool_path(stats, 'a')));
        CHECK(fs::exists(live_spool_path(stats, 'b')));
    }
    fs::remove_all(stats);
}

TEST_CASE("shutdown drains queued live candidates before persisting block credit") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_final_block_stats_test";
    fs::remove_all(stats);
    Config config;
    config.stats_directory = stats.string();
    BlockingLiveWorkSource source;
    source.response = std::nullopt;
    SUBCASE("accepted blocks") {}
    SUBCASE("already known blocks") { source.response = "duplicate"; }
    SUBCASE("an in-flight failure is retried successfully") {
        source.first_attempt_inconclusive = true;
    }
    SUBCASE("an in-flight failure is already known on retry") {
        source.first_attempt_inconclusive = true;
        source.response = "duplicate";
    }

    {
        Pool pool(config, source, test::kWorkGeneration);
        enqueue_live_block(pool, 'f');
        const bool submission_started =
            source.submission_started.try_acquire_for(kSynchronizationTimeout);
        if (!submission_started)
            source.continue_submission.release();
        REQUIRE(submission_started);
        enqueue_live_block(pool, 'a');
        enqueue_live_block(pool, 'b');
        enqueue_live_block(pool, 'a');
        CHECK(PoolTestPeek::pending_live_submissions(pool) == 3);

        std::jthread status_thread([&pool](const std::stop_token& stop) { pool.status_loop(stop); });
        status_thread.request_stop();
        status_thread.join();
        CHECK(pool.blocks_found() == 0);

        std::binary_semaphore stop_requested{0};
        std::stop_callback stop_callback(PoolTestPeek::live_submission_stop_token(pool),
                                        [&stop_requested] { stop_requested.release(); });
        auto shutdown = std::async(std::launch::async, [&pool] { pool.shutdown(); });
        const bool stop_observed = stop_requested.try_acquire_for(kSynchronizationTimeout);
        const auto blocked_state = shutdown.wait_for(std::chrono::seconds::zero());
        source.continue_submission.release();

        REQUIRE(stop_observed);
        CHECK(blocked_state == std::future_status::timeout);
        REQUIRE(shutdown.wait_for(kSynchronizationTimeout) == std::future_status::ready);
        CHECK_NOTHROW(shutdown.get());
        const auto recovered = stats::read_pool_status(config.stats_directory);
        REQUIRE(recovered.has_value());
        CHECK(recovered->blocks_found == 3);
        CHECK(recovered->blocks_by_address.at(kAddr) == 3);
        CHECK(PoolTestPeek::pending_live_submissions(pool) == 0);
        CHECK(PoolTestPeek::pending_recovered_submissions(pool) == 0);
        const size_t expected_submissions = source.first_attempt_inconclusive ? 5 : 4;
        CHECK(source.submissions.load(std::memory_order_relaxed) == expected_submissions);

        pool.shutdown();
        CHECK(source.submissions.load(std::memory_order_relaxed) == expected_submissions);
        CHECK(pool.blocks_found() == 3);
    }
    fs::remove_all(stats);
}

TEST_CASE("shutdown gives deferred live blocks one final attempt without waiting") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_final_live_retry_test";
    fs::remove_all(stats);
    Config config;
    config.stats_directory = stats.string();
    BlockingLiveWorkSource source;
    source.first_attempt_inconclusive = true;
    source.continue_submission.release();
    int64_t expected_blocks = 0;
    SUBCASE("accepted") {
        source.response = std::nullopt;
        expected_blocks = 1;
    }
    SUBCASE("already known") {
        source.response = "duplicate";
        expected_blocks = 1;
    }
    SUBCASE("inconclusive") {}
    SUBCASE("transport error") { source.fail_submission = true; }

    {
        Pool pool(config, source, test::kWorkGeneration);
        PoolTestPeek::stop_recovery_worker(pool);
        enqueue_live_block(pool, 'c');
        REQUIRE(wait_until([&] { return PoolTestPeek::pending_recovered_submissions(pool) == 1; }));
        PoolTestPeek::stop_workers(pool);
        PoolTestPeek::delay_recovered_submissions(pool);
        REQUIRE(source.submissions.load(std::memory_order_relaxed) == 1);

        const auto started = std::chrono::steady_clock::now();
        pool.shutdown();
        CHECK(std::chrono::steady_clock::now() - started < kSynchronizationTimeout);
        CHECK(source.submissions.load(std::memory_order_relaxed) == 2);
        CHECK(PoolTestPeek::pending_recovered_submissions(pool) == 0);
        CHECK(fs::exists(live_spool_path(stats, 'c')));
        const auto recovered = stats::read_pool_status(config.stats_directory);
        REQUIRE(recovered.has_value());
        CHECK(recovered->blocks_found == expected_blocks);
        if (expected_blocks > 0)
            CHECK(recovered->blocks_by_address.at(kAddr) == expected_blocks);
        else
            CHECK(recovered->blocks_by_address.empty());

        pool.shutdown();
        CHECK(source.submissions.load(std::memory_order_relaxed) == 2);
        CHECK(pool.blocks_found() == expected_blocks);
    }
    fs::remove_all(stats);
}

TEST_CASE("shutdown retries an in-flight live recovery failure before persisting block credit") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_final_inflight_retry_test";
    fs::remove_all(stats);
    Config config;
    config.stats_directory = stats.string();
    BlockingRetryWorkSource source;
    source.retry_response = "inconclusive";

    {
        Pool pool(config, source, test::kWorkGeneration);
        enqueue_live_block(pool, 'd');
        if (wait_until([&] { return PoolTestPeek::pending_recovered_submissions(pool) == 1; }))
            PoolTestPeek::retry_recovered_submissions_now(pool);
        const bool retry_started = source.retry_started.try_acquire_for(kSynchronizationTimeout);
        if (!retry_started)
            source.continue_retry.release();
        REQUIRE(retry_started);

        std::binary_semaphore stop_requested{0};
        std::stop_callback stop_callback(PoolTestPeek::recovery_submission_stop_token(pool),
                                        [&stop_requested] { stop_requested.release(); });
        auto shutdown = std::async(std::launch::async, [&pool] { pool.shutdown(); });
        const bool stop_observed = stop_requested.try_acquire_for(kSynchronizationTimeout);
        const auto blocked_state = shutdown.wait_for(std::chrono::seconds::zero());
        source.continue_retry.release();

        REQUIRE(stop_observed);
        CHECK(blocked_state == std::future_status::timeout);
        REQUIRE(shutdown.wait_for(kSynchronizationTimeout) == std::future_status::ready);
        CHECK_NOTHROW(shutdown.get());
        CHECK(source.submissions.load(std::memory_order_relaxed) == 3);
        CHECK(PoolTestPeek::pending_recovered_submissions(pool) == 0);
        const auto recovered = stats::read_pool_status(config.stats_directory);
        REQUIRE(recovered.has_value());
        CHECK(recovered->blocks_found == 1);
        CHECK(recovered->blocks_by_address.at(kAddr) == 1);
        CHECK(fs::exists(live_spool_path(stats, 'd')));
    }
    fs::remove_all(stats);
}

TEST_CASE("shutdown leaves historical recovered blocks for the next startup") {
    namespace fs = std::filesystem;
    const auto fixture = write_recovered_block("ep_recovered_shutdown_test");
    RecoveredBlockWorkSource source({
        .candidate_hash = fixture.block_hash,
        .tip_hash = fixture.block_hash,
    });
    Config config;
    config.stats_directory = fixture.stats_directory.string();

    {
        Pool pool(config, source, test::kWorkGeneration);
        PoolTestPeek::stop_workers(pool);
        pool.resubmit_spooled_blocks();
        REQUIRE(PoolTestPeek::pending_recovered_submissions(pool) == 1);

        pool.shutdown();
        pool.shutdown();
        CHECK(source.submissions.load(std::memory_order_relaxed) == 0);
        CHECK(source.tip_lookups.load(std::memory_order_relaxed) == 0);
        CHECK(fs::exists(fixture.spool_path));
        CHECK_FALSE(fs::exists(fixture.spool_path.string() + ".submitted"));
        CHECK_FALSE(fs::exists(fixture.spool_path.string() + ".stale"));
        CHECK(pool.blocks_found() == 0);
        const auto recovered = stats::read_pool_status(config.stats_directory);
        REQUIRE(recovered.has_value());
        CHECK(recovered->blocks_found == 0);
        CHECK(recovered->blocks_by_address.empty());
    }
    fs::remove_all(fixture.stats_directory);
}

TEST_CASE("Pool destruction joins an in-flight live submission without retrying") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_live_submission_shutdown_test";
    fs::remove_all(stats);
    Config config;
    config.stats_directory = stats.string();
    BlockingLiveWorkSource source;
    auto pool = std::make_unique<Pool>(config, source, test::kWorkGeneration);
    const std::stop_token submit_stop = PoolTestPeek::live_submission_stop_token(*pool);

    enqueue_live_block(*pool, 'f');
    const bool submission_started =
        source.submission_started.try_acquire_for(kSynchronizationTimeout);
    if (!submission_started)
        source.continue_submission.release();
    REQUIRE(submission_started);

    std::binary_semaphore stop_requested{0};
    std::stop_callback stop_callback(submit_stop, [&stop_requested] { stop_requested.release(); });
    auto destruction = std::async(std::launch::async, [owned_pool = std::move(pool)]() mutable {
        owned_pool.reset();
    });

    const bool stop_observed = stop_requested.try_acquire_for(kSynchronizationTimeout);
    const std::future_status blocked_state = destruction.wait_for(std::chrono::seconds::zero());
    source.continue_submission.release();

    REQUIRE(stop_observed);
    CHECK(blocked_state == std::future_status::timeout);
    REQUIRE(destruction.wait_for(kSynchronizationTimeout) == std::future_status::ready);
    CHECK_NOTHROW(destruction.get());
    CHECK(source.submissions.load(std::memory_order_relaxed) == 1);

    CHECK(fs::exists(live_spool_path(stats, 'f')));
    fs::remove_all(stats);
}

TEST_CASE("recovered blocks are submitted once before consulting the chain tip") {
    namespace fs = std::filesystem;
    const auto fixture = write_recovered_block("ep_recovered_first_submit_test");
    RecoveredBlockWorkSource source({
        .candidate_hash = fixture.block_hash,
        .tip_hash = fixture.block_hash,
    });
    Config config;
    config.stats_directory = fixture.stats_directory.string();

    {
        Pool pool(config, source, test::kWorkGeneration);
        REQUIRE(wait_for_first_recovered_submission(pool, source));
        CHECK(source.tip_lookups.load(std::memory_order_relaxed) == 0);
        CHECK(fs::exists(fixture.spool_path));
    }

    fs::remove_all(fixture.stats_directory);
}

TEST_CASE("a recovered block at the active tip is archived before a second submission") {
    namespace fs = std::filesystem;
    const auto fixture = write_recovered_block("ep_recovered_active_tip_test");
    RecoveredBlockWorkSource source({
        .candidate_hash = fixture.block_hash,
        .tip_hash = fixture.block_hash,
    });
    Config config;
    config.stats_directory = fixture.stats_directory.string();

    {
        Pool pool(config, source, test::kWorkGeneration);
        REQUIRE(wait_for_first_recovered_submission(pool, source));
        PoolTestPeek::retry_recovered_submissions_now(pool);
        REQUIRE(wait_until(
            [&] { return fs::exists(fixture.spool_path.string() + ".submitted"); }));
        CHECK(source.submissions.load(std::memory_order_relaxed) == 1);
    }

    CHECK_FALSE(fs::exists(fixture.spool_path));
    fs::remove_all(fixture.stats_directory);
}

TEST_CASE("a recovered block on the active chain is archived as submitted after the tip advances") {
    namespace fs = std::filesystem;
    const auto fixture = write_recovered_block("ep_recovered_active_ancestor_test");
    RecoveredBlockWorkSource source({
        .candidate_hash = fixture.block_hash,
        .tip_hash = std::string(64, 'f'),
        .tip_height = kRecoveredBlockHeight + 1,
        .candidate_confirmations = 2,
    });
    Config config;
    config.stats_directory = fixture.stats_directory.string();

    {
        Pool pool(config, source, test::kWorkGeneration);
        REQUIRE(wait_for_first_recovered_submission(pool, source));
        PoolTestPeek::retry_recovered_submissions_now(pool);
        REQUIRE(wait_until(
            [&] { return fs::exists(fixture.spool_path.string() + ".submitted"); }));
        CHECK(source.submissions.load(std::memory_order_relaxed) == 1);
        CHECK(source.candidate_header_lookups.load(std::memory_order_relaxed) == 1);
    }

    CHECK_FALSE(fs::exists(fixture.spool_path));
    fs::remove_all(fixture.stats_directory);
}

TEST_CASE("a recovered side-chain block is archived as stale after the tip advances") {
    namespace fs = std::filesystem;
    const auto fixture = write_recovered_block("ep_recovered_side_chain_test");
    RecoveredBlockWorkSource source({
        .candidate_hash = fixture.block_hash,
        .tip_hash = std::string(64, 'f'),
        .tip_height = kRecoveredBlockHeight + 1,
        .candidate_confirmations = -1,
    });
    Config config;
    config.stats_directory = fixture.stats_directory.string();

    {
        Pool pool(config, source, test::kWorkGeneration);
        REQUIRE(wait_for_first_recovered_submission(pool, source));
        PoolTestPeek::retry_recovered_submissions_now(pool);
        REQUIRE(wait_until(
            [&] { return fs::exists(fixture.spool_path.string() + ".stale"); }));
        CHECK(source.submissions.load(std::memory_order_relaxed) == 1);
        CHECK(source.candidate_header_lookups.load(std::memory_order_relaxed) == 1);
    }

    CHECK_FALSE(fs::exists(fixture.spool_path));
    fs::remove_all(fixture.stats_directory);
}

TEST_CASE("a recovered block retries when a different block is the tip at the same height") {
    namespace fs = std::filesystem;
    const auto fixture = write_recovered_block("ep_recovered_same_height_test");
    RecoveredBlockWorkSource source({
        .candidate_hash = fixture.block_hash,
        .tip_hash = std::string(64, 'f'),
    });
    Config config;
    config.stats_directory = fixture.stats_directory.string();

    {
        Pool pool(config, source, test::kWorkGeneration);
        REQUIRE(wait_for_first_recovered_submission(pool, source));
        PoolTestPeek::retry_recovered_submissions_now(pool);
        REQUIRE(wait_until(
            [&] { return source.submissions.load(std::memory_order_relaxed) == 2; }));
        CHECK(fs::exists(fixture.spool_path));
        CHECK_FALSE(fs::exists(fixture.spool_path.string() + ".stale"));
    }

    fs::remove_all(fixture.stats_directory);
}

TEST_CASE("a recovered block retries when the chain tip lookup fails") {
    namespace fs = std::filesystem;
    const auto fixture = write_recovered_block("ep_recovered_tip_failure_test");
    RecoveredBlockWorkSource source({
        .candidate_hash = fixture.block_hash,
        .tip_hash = fixture.block_hash,
        .fail_tip_lookup = true,
    });
    Config config;
    config.stats_directory = fixture.stats_directory.string();

    {
        Pool pool(config, source, test::kWorkGeneration);
        REQUIRE(wait_for_first_recovered_submission(pool, source));
        PoolTestPeek::retry_recovered_submissions_now(pool);
        REQUIRE(wait_until(
            [&] { return source.submissions.load(std::memory_order_relaxed) == 2; }));
        CHECK(fs::exists(fixture.spool_path));
        CHECK(source.tip_lookups.load(std::memory_order_relaxed) == 1);
    }

    fs::remove_all(fixture.stats_directory);
}

TEST_CASE("a recovered block retries when its filename hash does not match its header") {
    namespace fs = std::filesystem;
    const std::string filename_hash(64, 'f');
    const auto fixture =
        write_recovered_block("ep_recovered_mismatched_hash_test", filename_hash);
    RecoveredBlockWorkSource source({
        .candidate_hash = fixture.block_hash,
        .tip_hash = filename_hash,
    });
    Config config;
    config.stats_directory = fixture.stats_directory.string();

    {
        Pool pool(config, source, test::kWorkGeneration);
        REQUIRE(wait_for_first_recovered_submission(pool, source));
        PoolTestPeek::retry_recovered_submissions_now(pool);
        REQUIRE(wait_until(
            [&] { return source.submissions.load(std::memory_order_relaxed) == 2; }));
        CHECK(fs::exists(fixture.spool_path));
        CHECK_FALSE(fs::exists(fixture.spool_path.string() + ".submitted"));
        CHECK_FALSE(fs::exists(fixture.spool_path.string() + ".stale"));
    }

    fs::remove_all(fixture.stats_directory);
}

TEST_CASE("an archive failure leaves a terminal recovered block for the next restart") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_resubmit_archive_failure_test";
    const fs::path block = stats / "blocks" / "500_abc.hex";
    fs::remove_all(stats);
    fs::create_directories(block.parent_path());
    { std::ofstream(block, std::ios::binary) << "00112233\n"; }
    fs::create_directory(block.string() + ".submitted"); // force rename to fail

    Config config;
    config.stats_directory = stats.string();
    DuplicateRpc rpc;
    bitcoin::RpcWorkSource rpc_source(rpc);
    {
        Pool pool(config, rpc_source, test::kWorkGeneration);
        CHECK_FALSE(PoolTestPeek::submit_recovered(pool, block));
        CHECK(rpc.calls.load(std::memory_order_relaxed) == 1);
        CHECK(pool.blocks_found() == 0);
    }

    CHECK(fs::exists(block));
    fs::remove_all(stats);
}

TEST_CASE("a recovered block retries in-process without duplicate enqueue or accounting credit") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_resubmit_retry_test";
    fs::remove_all(stats);
    fs::create_directories(stats / "blocks");
    const fs::path block = stats / "blocks" / "500_abc.hex";
    { std::ofstream(block, std::ios::binary) << "00112233\n"; }

    Config config;
    config.stats_directory = stats.string();
    RecoveringRpc rpc;
    bitcoin::RpcWorkSource rpc_source(rpc);
    {
        Pool pool(config, rpc_source, test::kWorkGeneration);
        pool.resubmit_spooled_blocks();
        REQUIRE(wait_until([&] { return rpc.calls.load(std::memory_order_relaxed) == 1; }));
        REQUIRE(
            wait_until([&] { return PoolTestPeek::pending_recovered_submissions(pool) == 1; }));

        pool.resubmit_spooled_blocks();
        CHECK(PoolTestPeek::pending_recovered_submissions(pool) == 1);

        PoolTestPeek::retry_recovered_submissions_now(pool);
        REQUIRE(wait_until([&] { return fs::exists(block.string() + ".submitted"); }));
        CHECK(rpc.calls.load(std::memory_order_relaxed) == 2);
        CHECK(pool.blocks_found() == 0);
    }

    CHECK_FALSE(fs::exists(block));
    fs::remove_all(stats);
}

TEST_CASE("a recovered duplicate archives as submitted without accounting credit") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_resubmit_duplicate_test";
    fs::remove_all(stats);
    fs::create_directories(stats / "blocks");
    const fs::path block = stats / "blocks" / "500_abc.hex";
    { std::ofstream(block, std::ios::binary) << "00112233\n"; }

    Config config;
    config.stats_directory = stats.string();
    DuplicateRpc rpc;
    bitcoin::RpcWorkSource rpc_source(rpc);
    {
        Pool pool(config, rpc_source, test::kWorkGeneration);
        pool.resubmit_spooled_blocks();
        REQUIRE(wait_until([&] { return fs::exists(block.string() + ".submitted"); }));
        CHECK(pool.blocks_found() == 0);
    }

    CHECK_FALSE(fs::exists(block));
    fs::remove_all(stats);
}

TEST_CASE("a recovered rejection archives as rejected") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_resubmit_rejected_test";
    fs::remove_all(stats);
    fs::create_directories(stats / "blocks");
    const fs::path block = stats / "blocks" / "500_abc.hex";
    { std::ofstream(block, std::ios::binary) << "00112233\n"; }

    Config config;
    config.stats_directory = stats.string();
    RejectingRpc rpc;
    bitcoin::RpcWorkSource rpc_source(rpc);
    {
        Pool pool(config, rpc_source, test::kWorkGeneration);
        pool.resubmit_spooled_blocks();
        REQUIRE(wait_until([&] { return fs::exists(block.string() + ".rejected"); }));
        CHECK(pool.blocks_found() == 0);
    }

    CHECK_FALSE(fs::exists(block));
    fs::remove_all(stats);
}

TEST_CASE("block submission starts before a failed spool completes and logs recovery hex") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() /
                           std::format("ep_block_dispatch_{}", static_cast<long>(::getpid()));
    const std::string hash(64, 'f');
    const fs::path blocks = stats / "blocks";
    const fs::path final_path = blocks / std::format("{}_{}.hex", 170, hash);
    const fs::path temporary_path =
        final_path.string() + ".tmp." + std::to_string(static_cast<long>(::getpid()));
    fs::remove_all(stats);
    fs::create_directories(blocks);
    REQUIRE(::mkfifo(temporary_path.c_str(), 0600) == 0);
    const fs::path log_path = stats / "spool.log";
    REQUIRE(log::set_log_file(log_path.string()));

    Config config;
    config.stats_directory = stats.string();
    FlappingWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    const Bytes tag{'/', 't', '/'};
    stratum::Job job("job", refresh_template(), tag, 4, 4, 1);
    stratum::ShareResult result;
    result.difficulty = 1.0;
    result.is_block = true;
    result.legacy_coinbase = {0};
    result.block_hash_chars.fill('f');

    std::atomic<bool> callback_finished{false};
    std::jthread callback([&] {
        pool.on_block_found(kAddr, "w", job, result);
        callback_finished.store(true, std::memory_order_release);
    });

    CHECK(wait_until([&] { return source.submissions.load(std::memory_order_acquire) == 1; }));
    CHECK_FALSE(callback_finished.load(std::memory_order_acquire));

    // A FIFO blocks the writer until opened, then makes fsync fail with EINVAL.
    const int fifo = ::open(temporary_path.c_str(), O_RDWR | O_NONBLOCK);
    REQUIRE(fifo >= 0);
    callback.join();
    ::close(fifo);
    log::set_log_file("");

    CHECK(callback_finished.load(std::memory_order_acquire));
    CHECK_FALSE(fs::exists(final_path));
    CHECK(fs::exists(temporary_path));
    std::ifstream log_input(log_path);
    std::stringstream log_contents;
    log_contents << log_input.rdbuf();
    const std::string contents = log_contents.str();
    CHECK(contents.contains("Could not spool block"));
    CHECK(contents.contains("fsync"));
    CHECK(contents.contains("HEX FOLLOWS: " +
                            job.build_block_hex(result.legacy_coinbase, result.header)));
    CHECK_FALSE(contents.contains("Spooled block to"));
    fs::remove_all(stats);
}

TEST_CASE("coinbase work identity separates jobs and restarts despite overlapping timestamps") {
    const Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource source(rpc);
    Pool first(config, source, test::kWorkGeneration);
    Pool restarted(config, source, test::kWorkGeneration + 1);
    const auto first_job = PoolTestPeek::make_job(first, refresh_template());
    const auto same_template = PoolTestPeek::make_job(first, refresh_template());
    auto later_template = refresh_template();
    ++later_template.curtime;
    const auto later_job = PoolTestPeek::make_job(first, later_template);
    const auto restarted_job = PoolTestPeek::make_job(restarted, refresh_template());
    const Bytes payout_script = *first.validate_address(kAddr);
    const Bytes extranonce(config.extranonce1_size + config.extranonce2_size, 0);

    const auto first_work = first_job->build_standard_work(payout_script, extranonce);
    for (const auto& job : {same_template, later_job, restarted_job}) {
        const auto work = job->build_standard_work(payout_script, extranonce);
        CHECK(work.legacy_coinbase != first_work.legacy_coinbase);
        CHECK(work.merkle_root != first_work.merkle_root);
        auto extended = job->build_extended_work(payout_script);
        append(extended.coinbase_tx_prefix, extranonce);
        append(extended.coinbase_tx_prefix, extended.coinbase_tx_suffix);
        CHECK(extended.coinbase_tx_prefix == work.legacy_coinbase);
    }
    const Bytes coinbase_suffix = first_job->build_coinbase2(payout_script);
    const auto identifier = ByteView(coinbase_suffix).subspan(
        config.coinbase_signature.size(), mining::kWorkIdentifierSize);
    CHECK(util::read_le64(identifier.data()) == test::kWorkGeneration);
    CHECK(util::read_le64(identifier.data() + sizeof(uint64_t)) == 1);

    stratum::StandardShareInput input;
    input.legacy_coinbase = first_work.legacy_coinbase;
    input.merkle_root = first_work.merkle_root;
    input.ntime = later_template.curtime;
    input.version = first_job->version();
    input.now_unix = later_template.curtime;
    input.share_target = util::uint256::from_le_bytes(Bytes(32, 0xff));
    const auto rolled_share = first_job->validate_standard_share(input);
    REQUIRE(rolled_share);
    const auto later_work = later_job->build_standard_work(payout_script, extranonce);
    input.legacy_coinbase = later_work.legacy_coinbase;
    input.merkle_root = later_work.merkle_root;
    const auto later_share = later_job->validate_standard_share(input);
    REQUIRE(later_share);
    CHECK(rolled_share->header != later_share->header);

    CHECK(first_job->work_signature() == same_template->work_signature());
    CHECK(first_job->work_signature() == restarted_job->work_signature());
    PoolTestPeek::publish(first, first_job);
    PoolTestPeek::publish(first, same_template);
    CHECK(first.current_job() == first_job);
    PoolTestPeek::publish(first, later_job);
    CHECK(first.current_job() == later_job);
}

TEST_CASE("pool coinbase extras are pushed data even when they contain sigop bytes") {
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource source(rpc);
    for (const std::size_t signature_size : {47u, 48u, 60u}) {
        Config config;
        config.coinbase_signature = std::string(signature_size, static_cast<char>(0xae));
        Pool pool(config, source, 0xaeaeaeaeaeaeaeaeULL);
        const auto job = PoolTestPeek::make_job(pool, refresh_template());
        const auto prefix = util::from_hex(job->coinbase1_hex());
        const std::size_t data_size = config.extranonce1_size + config.extranonce2_size +
                                      signature_size + mining::kWorkIdentifierSize;
        CHECK(prefix.back() == data_size);
        if (data_size > 75)
            CHECK(prefix[prefix.size() - 2] == 0x4c);
        const auto work = job->build_standard_work(
            *pool.validate_address(kAddr), Bytes(config.extranonce1_size + config.extranonce2_size, 0xae));
        // The entire pushed payload ends exactly where nSequence begins.
        CHECK(work.legacy_coinbase[prefix.size() + data_size] == 0xff);
        CHECK(work.legacy_coinbase[41] <= 100);
    }
}

TEST_CASE("pool refuses reused session and job counters without dropping existing miners") {
    const Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource source(rpc);
    Pool pool(config, source, test::kWorkGeneration);
    PoolTestPeek::seed_extranonce_counter(pool, std::numeric_limits<uint32_t>::max() - 1);
    const auto session = pool.add_client(std::make_shared<TestConnection>());
    CHECK(session->extranonce1_hex() == "ffffffff");
    CHECK_THROWS_AS(pool.add_client(std::make_shared<TestConnection>()), std::overflow_error);
    CHECK_THROWS_AS(pool.add_sv2_client(std::make_shared<TestConnection>()), std::overflow_error);
    CHECK(pool.client_count() == 1);
    PoolTestPeek::exhaust_job_counter(pool);
    CHECK_THROWS_AS(pool.next_job_id(), std::overflow_error);
    CHECK_THROWS_AS(PoolTestPeek::make_job(pool, refresh_template()), std::overflow_error);
    CHECK_THROWS_AS(Pool(Config{}, source, 0), std::invalid_argument);
}

TEST_CASE("SV2 publication worker is opt-in") {
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);

    Pool sv1_pool(Config{}, rpc_source, test::kWorkGeneration);
    CHECK_FALSE(PoolTestPeek::publication_worker_started(sv1_pool));

    Pool sv2_pool(sv2_publication_config(), rpc_source, test::kWorkGeneration);
    CHECK(PoolTestPeek::publication_worker_started(sv2_pool));
}

TEST_CASE("SV2 publication cannot delay SV1 work delivery") {
    Config config = sv2_publication_config();
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);

    auto delayed = std::make_shared<BlockingPublicationClient>();
    auto immediate = std::make_shared<RecordingPublicationClient>();
    PoolTestPeek::add_client(pool, delayed, true);
    PoolTestPeek::add_client(pool, immediate, false);

    const auto job = publication_job("broadcast-order", 1);
    auto broadcast = std::async(std::launch::async,
                                [&] { PoolTestPeek::publish(pool, job); });

    CHECK(delayed->entered.try_acquire_for(std::chrono::seconds(1)));
    const bool broadcast_finished =
        broadcast.wait_for(std::chrono::milliseconds(100)) ==
        std::future_status::ready;
    delayed->proceed.release();

    broadcast.get();
    CHECK(delayed->completed.try_acquire_for(std::chrono::seconds(1)));
    CHECK(broadcast_finished);
    CHECK(immediate->calls.load(std::memory_order_relaxed) == 1);
    CHECK(delayed->calls.load(std::memory_order_relaxed) == 1);
}

TEST_CASE("deferred SV2 publication coalesces to the newest clean work") {
    Config config = sv2_publication_config();
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);

    auto delayed = std::make_shared<BlockingPublicationClient>();
    PoolTestPeek::add_client(pool, delayed, true);
    const auto first = publication_job("first", 1);
    const auto clean = publication_job("clean", 2);
    const auto newest = publication_job("newest", 3);

    PoolTestPeek::enqueue(pool, delayed, first, false);
    CHECK(delayed->entered.try_acquire_for(std::chrono::seconds(1)));
    PoolTestPeek::enqueue(pool, delayed, clean, true);
    PoolTestPeek::enqueue(pool, delayed, newest, false);
    delayed->proceed.release();

    CHECK(delayed->completed.try_acquire_for(std::chrono::seconds(1)));
    CHECK(delayed->completed.try_acquire_for(std::chrono::seconds(1)));
    REQUIRE(delayed->job_ids.size() == 2);
    REQUIRE(delayed->clean_flags.size() == 2);
    CHECK(delayed->job_ids[0] == "first");
    CHECK(delayed->job_ids[1] == "newest");
    CHECK_FALSE(delayed->clean_flags[0]);
    CHECK(delayed->clean_flags[1]);
}

TEST_CASE("deferred SV2 publication preserves clean from late older work") {
    Config config = sv2_publication_config();
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);

    auto delayed = std::make_shared<BlockingPublicationClient>();
    PoolTestPeek::add_client(pool, delayed, true);

    PoolTestPeek::enqueue(
        pool, delayed, publication_job("blocking", 1), false);
    CHECK(delayed->entered.try_acquire_for(std::chrono::seconds(1)));
    PoolTestPeek::enqueue(
        pool, delayed, publication_job("newest", 3), false);
    PoolTestPeek::enqueue(
        pool, delayed, publication_job("late-clean", 2), true);
    delayed->proceed.release();

    CHECK(delayed->completed.try_acquire_for(std::chrono::seconds(1)));
    CHECK(delayed->completed.try_acquire_for(std::chrono::seconds(1)));
    REQUIRE(delayed->job_ids.size() == 2);
    REQUIRE(delayed->clean_flags.size() == 2);
    CHECK(delayed->job_ids[1] == "newest");
    CHECK(delayed->clean_flags[1]);
}

TEST_CASE("disconnect removes queued SV2 publication") {
    Config config = sv2_publication_config();
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);

    auto delayed = std::make_shared<BlockingPublicationClient>();
    auto disconnected = std::make_shared<RecordingPublicationClient>();
    PoolTestPeek::add_client(pool, delayed, true);
    PoolTestPeek::add_client(pool, disconnected, true);

    PoolTestPeek::enqueue(pool, delayed, publication_job("blocking", 1), false);
    CHECK(delayed->entered.try_acquire_for(std::chrono::seconds(1)));
    PoolTestPeek::enqueue(pool, disconnected, publication_job("removed", 2), true);
    pool.remove_client(disconnected);
    delayed->proceed.release();

    CHECK(delayed->completed.try_acquire_for(std::chrono::seconds(1)));
    CHECK_FALSE(disconnected->called.try_acquire_for(
        std::chrono::milliseconds(100)));
    CHECK(disconnected->calls.load(std::memory_order_relaxed) == 0);
}

// A block the pool genuinely won must be credited even when the ACCEPTING reply never arrives.
// On a flaky node link bitcoind accepts the submit but its response is lost; the pool retries and
// gets "duplicate", so "duplicate" is the ONLY reply it ever sees. Counting solely on ACCEPTED
// under-reported blocks_found/blocks_by_address permanently (they persist via pool.status).
TEST_CASE("a block whose accepting reply was lost is still credited exactly once") {
    Config config;
    DuplicateRpc rpc; // every submit answers "duplicate"
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);
    const std::string hash(64, 'b');

    CHECK_FALSE(PoolTestPeek::submit(pool, hash, kAddr)); // terminal, no retry
    CHECK(pool.blocks_found() == 1);                      // credited off "duplicate" alone
    CHECK(pool.snapshot().blocks_by_address.at(kAddr) == 1);

    // Re-offering the SAME block (fastblock+GBT double-submit, or a replay) must not double-count.
    CHECK_FALSE(PoolTestPeek::submit(pool, hash, kAddr));
    CHECK(pool.blocks_found() == 1);
    CHECK(pool.snapshot().blocks_by_address.at(kAddr) == 1);

    // A genuinely different block is credited on its own.
    CHECK_FALSE(PoolTestPeek::submit(pool, std::string(64, 'c'), kAddr));
    CHECK(pool.blocks_found() == 2);
    CHECK(pool.snapshot().blocks_by_address.at(kAddr) == 2);
}

// The real flaky-link sequence: the submit reaches Core and is accepted, but the reply is lost at
// the transport. The pool retries and only ever sees "duplicate" -- which must still credit.
TEST_CASE("a lost reply followed by duplicate credits the block on the retry") {
    Config config;
    LostReplyThenDuplicateRpc rpc;
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);
    const std::string hash(64, 'd');

    CHECK(PoolTestPeek::submit(pool, hash, kAddr)); // transport died -> retry requested
    CHECK(pool.blocks_found() == 0);                // nothing credited yet
    CHECK_FALSE(PoolTestPeek::submit(pool, hash, kAddr)); // retry sees "duplicate" -> terminal
    CHECK(pool.blocks_found() == 1);                      // credited exactly once
    CHECK(pool.snapshot().blocks_by_address.at(kAddr) == 1);
}

// "duplicate-inconclusive" means Core knows the block but has NOT fully validated it. It is not a
// win yet: crediting it would count an unresolved block, and treating it as terminal would stop the
// retry that gets the real answer.
TEST_CASE("duplicate-inconclusive is retryable and is never credited") {
    Config config;
    DuplicateInconclusiveRpc rpc;
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);

    CHECK(PoolTestPeek::submit(pool, std::string(64, 'e'), kAddr)); // retry requested
    CHECK(pool.blocks_found() == 0);                                // NOT credited
    CHECK(pool.snapshot().blocks_by_address.empty());
}

TEST_CASE("worker snapshots do not block unrelated authorization") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);
    auto accounting = pool.attach_worker(kAddr, "blocked");
    REQUIRE(accounting);

    std::future<api::PoolSnapshot> sampling;
    std::future<stats::WorkerAccountingHandle> attaching;
    auto row_lock = stats::WorkerAccountingTestPeek::lock_row(*accounting);
    sampling = std::async(std::launch::async, [&] { return pool.snapshot(true); });
    const bool copied_row = wait_until([&] { return accounting.use_count() > 2; });
    attaching = std::async(std::launch::async,
                           [&] { return pool.attach_worker(kAddr, "new-worker"); });
    const bool attached_while_blocked =
        attaching.wait_for(kSynchronizationTimeout) == std::future_status::ready;
    const bool snapshot_waited =
        sampling.wait_for(std::chrono::seconds(0)) == std::future_status::timeout;
    row_lock.unlock();
    const auto attached = attaching.get();
    const auto snapshot = sampling.get();

    CHECK(copied_row);
    CHECK(attached_while_blocked);
    CHECK(snapshot_waited);
    REQUIRE(attached);
    const auto rows = workers_of(snapshot, kAddr);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front().worker == "blocked");
    CHECK(workers_of(pool.snapshot(true), kAddr).size() == 2);
}

TEST_CASE("pruning does not wait on a pinned worker accounting mutex") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);
    auto accounting = pool.attach_worker(kAddr, "blocked");
    REQUIRE(accounting);
    const int64_t much_later = static_cast<int64_t>(std::time(nullptr)) + 10 * 86400;

    std::future<void> pruning;
    auto row_lock = stats::WorkerAccountingTestPeek::lock_row(*accounting);
    pruning = std::async(std::launch::async, [&] { PoolTestPeek::prune(pool, much_later); });
    const bool pruned_while_blocked =
        pruning.wait_for(kSynchronizationTimeout) == std::future_status::ready;
    row_lock.unlock();
    pruning.get();

    CHECK(pruned_while_blocked);
    CHECK(workers_of(pool.snapshot(true), kAddr).size() == 1);
}

TEST_CASE("prune keeps a held worker row and evicts it once the last handle is gone") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_prune_pin_test";
    fs::remove_all(stats);
    Config config;
    config.stats_directory = stats.string();
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);

    auto accounting = pool.attach_worker(kAddr, "w1"); // an authorized Session holds this handle
    REQUIRE(accounting);
    REQUIRE(workers_of(pool.snapshot(true), kAddr).size() == 1);
    fs::create_directories(stats / "users");
    const auto user_file = stats / "users" / kAddr;
    std::ofstream(user_file) << "old stats\n";
    REQUIRE(fs::exists(user_file));

    const int64_t much_later = static_cast<int64_t>(std::time(nullptr)) + 10 * 86400;

    // Held (a live session still owns the row): never evicted, however stale the clock says it is.
    PoolTestPeek::prune(pool, much_later);
    CHECK(workers_of(pool.snapshot(true), kAddr).size() == 1);
    CHECK(fs::exists(user_file));

    // Handle released (session gone): the map is the sole owner, so the stale row is evicted.
    accounting.reset();
    PoolTestPeek::prune(pool, much_later);
    CHECK(workers_of(pool.snapshot(true), kAddr).empty());
    CHECK_FALSE(fs::exists(user_file));

    fs::remove_all(stats);
}

TEST_CASE("share hooks accumulate persistent per-worker stats; sessions with one name merge") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);

    // Two connections share worker name "w1"; a third is "w2". They must MERGE by name.
    pool.note_accepted_share(kAddr, "w1", 5.0, 5.0);
    pool.note_accepted_share(kAddr, "w1", 3.0, 3.0);
    pool.note_rejected_share(kAddr, "w1", stratum::RejectClass::Duplicate);
    pool.note_accepted_share(kAddr, "w2", 1.0, 1.0);

    const auto rows = workers_of(pool.snapshot(true), kAddr);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].worker == "w1");
    CHECK(rows[0].shares_accepted == 2);   // merged across the two w1 connections
    CHECK(rows[0].shares_rejected == 1);
    CHECK(rows[0].best_difficulty == doctest::Approx(5.0));
    CHECK(rows[0].hashrate_windows[0] > 0.0); // a fresh share registers hashrate
    CHECK(rows[1].worker == "w2");
    CHECK(rows[1].shares_accepted == 1);
}

TEST_CASE("cached worker accounting remains exact while writers and snapshots run concurrently") {
    constexpr int kWriterCount = 8;
    constexpr int kSharesPerWriter = 5000;

    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);

    std::vector<std::string> workers;
    std::vector<stats::WorkerAccountingHandle> accounting;
    workers.reserve(kWriterCount);
    accounting.reserve(kWriterCount);
    for (int writer = 0; writer < kWriterCount; ++writer) {
        workers.push_back("writer" + std::to_string(writer));
        accounting.push_back(pool.attach_worker(kAddr, workers.back()));
        REQUIRE(accounting.back());
    }

    std::atomic<bool> start{false};
    std::atomic<bool> stop_snapshots{false};
    std::atomic<bool> snapshots_valid{true};
    std::jthread snapshotter([&] {
        start.wait(false);
        while (!stop_snapshots.load(std::memory_order_relaxed)) {
            const auto current = pool.snapshot();
            uint64_t rejected_by_class = 0;
            for (const uint64_t count : current.shares_rejected_by_class)
                rejected_by_class += count;
            if (!std::isfinite(current.accepted_diff) || current.accepted_diff < 0.0 ||
                current.shares_rejected != rejected_by_class)
                snapshots_valid.store(false, std::memory_order_relaxed);
        }
    });

    std::vector<std::jthread> writers_threads;
    writers_threads.reserve(kWriterCount);
    for (int writer = 0; writer < kWriterCount; ++writer) {
        writers_threads.emplace_back([&, writer] {
            start.wait(false);
            const auto reason =
                static_cast<stratum::RejectClass>(writer % stratum::kRejectClassCount);
            for (int share = 0; share < kSharesPerWriter; ++share) {
                pool.note_accepted_share(accounting[writer], kAddr, workers[writer], 1.0,
                                         static_cast<double>(writer + 1));
                pool.note_rejected_share(accounting[writer], kAddr, workers[writer], reason);
            }
        });
    }
    start.store(true);
    start.notify_all();
    for (auto& writer : writers_threads)
        writer.join();
    stop_snapshots.store(true, std::memory_order_relaxed);
    snapshotter.join();

    CHECK(snapshots_valid.load(std::memory_order_relaxed));
    const auto final = pool.snapshot(true);
    const uint64_t expected = kWriterCount * kSharesPerWriter;
    CHECK(final.shares_accepted == expected);
    CHECK(final.shares_rejected == expected);
    CHECK(final.accepted_diff == doctest::Approx(static_cast<double>(expected)));
    CHECK(final.best_share == doctest::Approx(static_cast<double>(kWriterCount)));
    CHECK(final.hashrate_windows[0] > 0.0);
    CHECK(final.sps_windows[0] > 0.0);

    const auto rows = workers_of(final, kAddr);
    REQUIRE(rows.size() == kWriterCount);
    for (int writer = 0; writer < kWriterCount; ++writer) {
        CHECK(rows[writer].worker == workers[writer]);
        CHECK(rows[writer].shares_accepted == kSharesPerWriter);
        CHECK(rows[writer].shares_rejected == kSharesPerWriter);
        CHECK(rows[writer].best_difficulty == doctest::Approx(static_cast<double>(writer + 1)));
    }
    for (std::size_t reason = 0; reason < stratum::kRejectClassCount; ++reason) {
        const uint64_t writers_for_reason =
            (kWriterCount + stratum::kRejectClassCount - 1 - reason) /
            stratum::kRejectClassCount;
        CHECK(final.shares_rejected_by_class[reason] ==
              writers_for_reason * kSharesPerWriter);
    }
}

TEST_CASE("a connected overflow worker stays attached to its canonical bare bucket") {
    Config config;
    config.max_workers_per_address = 2;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);

    std::vector<std::shared_ptr<stratum::Session>> sessions;
    for (const std::string worker : {"w1", "w2", "overflow"}) {
        auto session = pool.add_client(std::make_shared<TestConnection>());
        session->handle_line(std::format(
            R"({{"id":1,"method":"mining.authorize","params":["{}.{}","x"]}})", kAddr, worker));
        REQUIRE(session->authorized());
        sessions.push_back(std::move(session));
    }

    const auto rows = workers_of(pool.snapshot(true), kAddr);
    REQUIRE(rows.size() == 3);
    CHECK(rows[0].worker == "");
    CHECK(rows[0].connected);
    CHECK(rows[1].worker == "w1");
    CHECK(rows[1].connected);
    CHECK(rows[2].worker == "w2");
    CHECK(rows[2].connected);
}

TEST_CASE("per-worker bestshare is the actual hash difficulty, not the credited target") {
    // A best share is by definition far above the share target; the registry must record the
    // actual difficulty met (share_difficulty), not the credited target, or it under-reports.
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);
    pool.note_accepted_share(kAddr, "w1", /*credited=*/8.0, /*share_difficulty=*/5000.0);
    pool.note_accepted_share(kAddr, "w1", /*credited=*/8.0, /*share_difficulty=*/120.0);
    const auto rows = workers_of(pool.snapshot(true), kAddr);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].best_difficulty == doctest::Approx(5000.0)); // max actual, not the 8.0 credited
    CHECK(rows[0].shares_accepted == 2);
}

TEST_CASE("a worker row persists in the registry after its connection ends") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);
    pool.note_accepted_share(kAddr, "rig", 4.0, 4.0);

    // snapshot() has no live clients (none were attached), yet the row is present: persistence.
    const auto rows = workers_of(pool.snapshot(true), kAddr);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].worker == "rig");
    CHECK(rows[0].shares_accepted == 1);
    CHECK_FALSE(rows[0].connected); // no live session, but the stats survive
}

TEST_CASE("attach_worker creates a zero row so an idle authorized worker appears") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);
    pool.attach_worker(kAddr, "idle");
    const auto rows = workers_of(pool.snapshot(true), kAddr);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].worker == "idle");
    CHECK(rows[0].shares_accepted == 0);
}

TEST_CASE("worker names beyond max_workers_per_address fold into the bare-address bucket") {
    Config config;
    config.max_workers_per_address = 2;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool pool(config, rpc_source, test::kWorkGeneration);
    pool.note_accepted_share(kAddr, "w1", 1.0, 1.0);
    pool.note_accepted_share(kAddr, "w2", 1.0, 1.0);
    pool.note_accepted_share(kAddr, "w3", 7.0, 7.0); // over the cap -> folds into ""
    pool.note_accepted_share(kAddr, "w4", 1.0, 1.0); // also folds

    const auto rows = workers_of(pool.snapshot(true), kAddr);
    REQUIRE(rows.size() == 3); // "" (bucket), w1, w2
    CHECK(rows[0].worker == "");
    CHECK(rows[0].shares_accepted == 2);            // w3 + w4
    CHECK(rows[0].best_difficulty == doctest::Approx(7.0));
    CHECK(rows[1].worker == "w1");
    CHECK(rows[2].worker == "w2");
}

TEST_CASE("recover_user_stats re-seeds the registry from users/ files, decayed by file age") {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "ep_recover_userstats";
    fs::remove_all(dir);

    // Write a users/<addr> file via the normal path so the format matches exactly.
    {
        Config wcfg;
        wcfg.stats_directory = dir.string();
        bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
        Pool writer(wcfg, rpc_source, test::kWorkGeneration);
        for (int i = 0; i < 20; ++i)
            writer.note_accepted_share(kAddr, "rig", 1000.0, 1000.0); // build up some hashrate
        const auto snap = writer.snapshot(/*include_workers=*/true);
        stats::write_user_files(dir.string(), snap);
    }
    REQUIRE(fs::exists(dir / "users" / kAddr));

    // A fresh pool recovers it.
    Config rcfg;
    rcfg.stats_directory = dir.string();
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    bitcoin::RpcWorkSource rpc_source(rpc);
    Pool reader(rcfg, rpc_source, test::kWorkGeneration);
    reader.recover_user_stats();

    const auto rows = workers_of(reader.snapshot(true), kAddr);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].worker == "rig");
    CHECK(rows[0].shares_accepted == 20);   // shares recovered exactly
    CHECK(rows[0].best_difficulty == doctest::Approx(1000.0));
    CHECK(rows[0].hashrate_windows[0] > 0.0); // hashrate recovered (decayed, but non-zero)

    fs::remove_all(dir);
}

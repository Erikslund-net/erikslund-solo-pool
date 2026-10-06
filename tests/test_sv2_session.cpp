#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <future>
#include <limits>
#include <memory>
#include <optional>
#include <semaphore>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "bitcoin/block_template.hpp"
#include "gbt_fixture.hpp"
#include "stratum/job.hpp"
#include "stratum/session.hpp"
#include "sv2/connection.hpp"
#include "sv2/messages.hpp"
#include "sv2/session.hpp"
#include "util/difficulty.hpp"
#include "util/hex.hpp"
#include "util/uint256.hpp"

using namespace erikslund;
using namespace erikslund::test;

namespace erikslund::sv2 {
struct SessionTestPeek {
    static void seed_extranonce(Session& session, uint64_t value) {
        session.extranonce_counter_ = value;
    }
    static void seed_job_id(Session& session, uint32_t value) {
        session.next_job_id_ = value;
    }
};
} // namespace erikslund::sv2

namespace {

const Bytes kPayoutScript =
    util::from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");

std::shared_ptr<stratum::Job>
make_job(uint32_t curtime, std::string_view bits = "1d00ffff",
         std::string previous_block_hash = std::string(64, '0')) {
    gbt_json value = gbt_json::object_t{};
    value["height"] = 200;
    value["version"] = 0x20000000;
    value["curtime"] = curtime;
    value["bits"] = std::string(bits);
    value["coinbasevalue"] = 5000000000LL;
    value["previousblockhash"] = std::move(previous_block_hash);
    value["transactions"] = gbt_json::array_t{};
    const Bytes tag{'/', 'e', 'p', '/'};
    return std::make_shared<stratum::Job>(
        "source-job", from_template(value), tag, 4, 8, 1);
}

class FakeConnection final : public sv2::Connection {
public:
    void send_bytes(ByteView bytes) override {
        append(wire, bytes);
    }

    std::string peer() const override {
        return "127.0.0.1:3334";
    }

    std::vector<sv2::Frame> take_frames() {
        sv2::FrameDecoder decoder;
        std::vector<sv2::Frame> frames = decoder.push(wire);
        decoder.finish();
        wire.clear();
        return frames;
    }

private:
    Bytes wire;
};

class FakePool final : public stratum::PoolContext {
public:
    explicit FakePool(uint32_t curtime) : job(make_job(curtime)) {}

    size_t extranonce2_size() const override {
        return extranonce_size;
    }
    std::shared_ptr<const RuntimeConfig> runtime_config() const override {
        RuntimeConfig config = Config{}.runtime_config();
        config.initial_difficulty = initial_difficulty;
        config.minimum_difficulty = minimum_difficulty;
        config.maximum_difficulty = maximum_difficulty;
        config.variable_difficulty = vardiff;
        config.vardiff_target_shares_per_minute = 1.0;
        config.vardiff_retarget_seconds = 0;
        return std::make_shared<const RuntimeConfig>(config);
    }
    std::optional<Bytes> validate_address(const std::string& address) override {
        return address == "validaddr" || address == "otheraddr"
                   ? std::optional<Bytes>(kPayoutScript)
                   : std::nullopt;
    }
    std::shared_ptr<const stratum::Job> current_job() const override {
        return job;
    }
    std::shared_ptr<const stratum::Job>
    recent_job(const std::string& job_id) const override {
        if (retained_job && retained_job->job_id() == job_id)
            return retained_job;
        return job && job->job_id() == job_id ? job : nullptr;
    }
    void note_accepted_share(const std::string&, const std::string&, double,
                             double) override {
        if (pause_next_accepted.exchange(false, std::memory_order_relaxed)) {
            accepted_entered.release();
            accepted_release.acquire();
        }
        ++accepted;
    }
    void note_rejected_share(const std::string&, const std::string&,
                             stratum::RejectClass) override {
        ++rejected;
    }
    void on_block_found(const std::string& address, const std::string& worker,
                        const stratum::Job& source,
                        const stratum::ShareResult& result) override {
        ++blocks;
        block_address = address;
        block_worker = worker;
        block_job = &source;
        block_result = result;
    }
    uint32_t version_mask() const override {
        return 0x1fffe000;
    }

    std::shared_ptr<stratum::Job> job;
    std::shared_ptr<stratum::Job> retained_job;
    size_t extranonce_size = 8;
    double initial_difficulty = 1e-9;
    double minimum_difficulty = 1e-12;
    double maximum_difficulty = 0.0;
    bool vardiff = false;
    std::atomic<bool> pause_next_accepted{false};
    std::binary_semaphore accepted_entered{0};
    std::binary_semaphore accepted_release{0};
    int accepted = 0;
    int rejected = 0;
    int blocks = 0;
    std::string block_address;
    std::string block_worker;
    const stratum::Job* block_job = nullptr;
    std::optional<stratum::ShareResult> block_result;
};

sv2::U256 maximum_target() {
    sv2::U256 value{};
    value.fill(0xff);
    return value;
}

void setup(sv2::Session& session,
           uint32_t flags =
               sv2::kSetupFlagRequiresStandardJobs |
                   sv2::kSetupFlagRequiresVersionRolling) {
    session.handle_bytes(sv2::encode_message(sv2::SetupConnection{
        sv2::kMiningProtocol, sv2::kProtocolVersion, sv2::kProtocolVersion,
        flags,
        "127.0.0.1", 3334, "test", "cpu", "1", "device"}));
}

void open_channel(sv2::Session& session, uint32_t request_id = 7,
                  float nominal_hash_rate = 1.0F) {
    session.handle_bytes(sv2::encode_message(sv2::OpenStandardMiningChannel{
        request_id, "validaddr.rig", nominal_hash_rate, maximum_target()}));
}

void open_extended_channel(sv2::Session& session, uint32_t request_id = 7,
                           float nominal_hash_rate = 1.0F,
                           uint16_t minimum_extranonce_size = 6,
                           std::string_view user_identity = "validaddr.rig") {
    session.handle_bytes(sv2::encode_message(sv2::OpenExtendedMiningChannel{
        request_id, std::string(user_identity), nominal_hash_rate, maximum_target(),
        minimum_extranonce_size}));
}

std::vector<uint32_t>
find_old_only_shares(const stratum::Job& job, const stratum::StandardWork& work,
                     const util::uint256& old_target,
                     const util::uint256& new_target, size_t count) {
    std::vector<uint32_t> found;
    for (uint32_t nonce = 0; nonce < 4096 && found.size() < count; ++nonce) {
        stratum::StandardShareInput input;
        input.legacy_coinbase = work.legacy_coinbase;
        input.merkle_root = work.merkle_root;
        input.ntime = job.curtime();
        input.nonce = nonce;
        input.version = job.version();
        input.version_mask = 0x1fffe000;
        input.share_target = old_target;
        input.now_unix = static_cast<int64_t>(std::time(nullptr));
        const auto old_result = job.validate_standard_share(input);
        if (!old_result)
            continue;
        input.share_target = new_target;
        const auto new_result = job.validate_standard_share(input);
        if (!new_result &&
            new_result.error().reason == stratum::ShareReject::AboveTarget)
            found.push_back(nonce);
    }
    return found;
}

std::vector<uint32_t>
find_old_only_shares(const stratum::Job& job, const stratum::ExtendedWork& work,
                     ByteView extranonce_prefix, ByteView extranonce,
                     const util::uint256& old_target,
                     const util::uint256& new_target, size_t count) {
    std::vector<uint32_t> found;
    for (uint32_t nonce = 0; nonce < 4096 && found.size() < count; ++nonce) {
        stratum::ExtendedShareInput input;
        input.extranonce_prefix = extranonce_prefix;
        input.extranonce = extranonce;
        input.extranonce_size = extranonce.size();
        input.ntime = job.curtime();
        input.nonce = nonce;
        input.version = job.version();
        input.version_mask = 0x1fffe000;
        input.share_target = old_target;
        input.now_unix = static_cast<int64_t>(std::time(nullptr));
        const auto old_result = job.validate_extended_share(work, input);
        if (!old_result)
            continue;
        input.share_target = new_target;
        const auto new_result = job.validate_extended_share(work, input);
        if (!new_result &&
            new_result.error().reason == stratum::ShareReject::AboveTarget)
            found.push_back(nonce);
    }
    return found;
}

} // namespace

TEST_CASE("SV2 opens a Standard Channel with the mandatory initial work order") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SetupConnectionSuccess::kMessageType);

    open_channel(session);
    frames = connection.take_frames();
    REQUIRE(frames.size() == 3);
    CHECK(frames[0].message_type ==
          sv2::OpenStandardMiningChannelSuccess::kMessageType);
    CHECK(frames[1].message_type == sv2::NewMiningJob::kMessageType);
    CHECK(frames[2].message_type == sv2::SetNewPrevHash::kMessageType);
    CHECK(session.authorized());

    open_channel(session, 8);
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(sv2::decode_open_mining_channel_error(frames[0].payload).error_code ==
          "channel-limit-reached");
    CHECK(session.protocol_errors() == 0);
}

TEST_CASE("SV2 refuses channel type changes even after all channels close") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    for (const bool standard_first : {true, false}) {
        FakePool pool(now);
        FakeConnection connection;
        sv2::Session session(pool, connection, util::from_hex("01020304"));
        setup(session, sv2::kSetupFlagRequiresVersionRolling);
        connection.take_frames();
        if (standard_first)
            open_channel(session);
        else
            open_extended_channel(session);
        REQUIRE(session.authorized());
        connection.take_frames();
        session.handle_bytes(sv2::encode_message(sv2::CloseChannel{1, "done"}));
        CHECK_FALSE(session.authorized());
        if (standard_first)
            open_extended_channel(session);
        else
            open_channel(session);
        const auto frames = connection.take_frames();
        REQUIRE(frames.size() == 1);
        CHECK(sv2::decode_open_mining_channel_error(frames[0].payload).error_code ==
              "channel-type-change-requires-reconnect");
        CHECK_FALSE(session.authorized());
    }
}

TEST_CASE("SV2 closes on extranonce exhaustion instead of repeating Standard work") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    for (const std::size_t width : {2u, 8u}) {
        FakePool pool(now);
        pool.extranonce_size = width;
        pool.job = std::make_shared<stratum::Job>(
            "source-job", from_template(gbt_json{{"height", 200}, {"version", 0x20000000},
                {"curtime", now}, {"bits", "1d00ffff"}, {"coinbasevalue", 5000000000LL},
                {"previousblockhash", std::string(64, '0')},
                {"transactions", gbt_json::array_t{}}}), Bytes{}, 4, width, 1);
        FakeConnection connection;
        sv2::Session session(pool, connection, util::from_hex("01020304"));
        setup(session);
        connection.take_frames();
        const uint64_t maximum = width == 2 ? 65535 : std::numeric_limits<uint64_t>::max();
        sv2::SessionTestPeek::seed_extranonce(session, maximum - 1);
        open_channel(session);
        const auto initial = connection.take_frames();
        REQUIRE(initial.size() == 3);
        const auto opened = sv2::decode_open_standard_mining_channel_success(initial[0].payload);
        CHECK(std::ranges::all_of(ByteView(opened.extranonce_prefix).subspan(4),
                                  [](uint8_t byte) { return byte == 0xff; }));
        CHECK_FALSE(session.should_close());
        pool.job->set_publication_sequence(1);
        session.publish_job(*pool.job, false);
        CHECK(session.should_close());
        CHECK(connection.take_frames().empty());
    }
}

TEST_CASE("SV2 job IDs never wrap back to an already issued handle") {
    FakePool pool(static_cast<uint32_t>(std::time(nullptr)));
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));
    setup(session);
    connection.take_frames();
    sv2::SessionTestPeek::seed_job_id(session, std::numeric_limits<uint32_t>::max());
    open_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    CHECK(sv2::decode_new_mining_job(initial[1].payload).job_id ==
          std::numeric_limits<uint32_t>::max());
    pool.job->set_publication_sequence(1);
    session.publish_job(*pool.job, false);
    CHECK(session.should_close());
    CHECK(connection.take_frames().empty());
}

TEST_CASE("SV2 opens independent Extended Channels with disjoint extranonces") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.extranonce_size = 8;
    FakeConnection connection;
    const Bytes connection_prefix = util::from_hex("01020304");
    sv2::Session session(pool, connection, connection_prefix);

    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    open_extended_channel(session, 7, 0.0F, 6, "validaddr.a");

    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 3);
    REQUIRE(frames[0].message_type ==
            sv2::OpenExtendedMiningChannelSuccess::kMessageType);
    const auto opened =
        sv2::decode_open_extended_mining_channel_success(frames[0].payload);
    Bytes expected_prefix_a = connection_prefix;
    expected_prefix_a.push_back(0);
    expected_prefix_a.push_back(1);
    CHECK(opened.channel_id == 1);
    CHECK(opened.extranonce_prefix == expected_prefix_a);
    CHECK(opened.extranonce_size == pool.extranonce2_size() - 2);
    CHECK(opened.group_channel_id == 0);

    REQUIRE(frames[1].message_type == sv2::NewExtendedMiningJob::kMessageType);
    const auto announced =
        sv2::decode_new_extended_mining_job(frames[1].payload);
    const stratum::ExtendedWork expected =
        pool.job->build_extended_work(kPayoutScript);
    CHECK(announced.channel_id == opened.channel_id);
    CHECK_FALSE(announced.minimum_ntime.has_value());
    CHECK(announced.version_rolling_allowed);
    CHECK(announced.merkle_path == expected.merkle_path);
    CHECK(announced.coinbase_tx_prefix == expected.coinbase_tx_prefix);
    CHECK(announced.coinbase_tx_suffix == expected.coinbase_tx_suffix);
    CHECK(frames[2].message_type == sv2::SetNewPrevHash::kMessageType);
    CHECK(session.authorized());
    CHECK(session.ever_authorized());

    session.maybe_refresh_job();
    CHECK(connection.take_frames().empty());

    open_channel(session, 8);
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(sv2::decode_open_mining_channel_error(frames[0].payload).error_code ==
          "channel-limit-reached");

    open_extended_channel(session, 9, 0.0F, 6, "otheraddr.b");
    frames = connection.take_frames();
    REQUIRE(frames.size() == 3);
    const auto opened_b =
        sv2::decode_open_extended_mining_channel_success(frames[0].payload);
    Bytes expected_prefix_b = connection_prefix;
    expected_prefix_b.push_back(0);
    expected_prefix_b.push_back(2);
    CHECK(opened_b.channel_id == 2);
    CHECK(opened_b.extranonce_prefix == expected_prefix_b);
    CHECK(opened_b.extranonce_prefix != opened.extranonce_prefix);
    CHECK(opened_b.extranonce_size == 6);
    CHECK(sv2::decode_new_extended_mining_job(frames[1].payload).channel_id ==
          opened_b.channel_id);
    CHECK(sv2::decode_set_new_prev_hash(frames[2].payload).channel_id ==
          opened_b.channel_id);

    const auto stats = session.stats();
    REQUIRE(stats.channels.size() == 2);
    CHECK(stats.channels[0].address == "validaddr");
    CHECK(stats.channels[1].address == "otheraddr");

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesStandard{
        opened.channel_id, 1, announced.job_id, 0, now, pool.job->version()}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(sv2::decode_submit_shares_error(frames[0].payload).error_code ==
          "invalid-channel-type");
}

TEST_CASE("SV2 routes Extended work updates closes and shares by channel") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.extranonce_size = 8;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    open_extended_channel(session, 7, 0.0F, 6, "validaddr.a");
    const auto initial_a = connection.take_frames();
    REQUIRE(initial_a.size() == 3);
    const auto opened_a =
        sv2::decode_open_extended_mining_channel_success(initial_a[0].payload);
    open_extended_channel(session, 8, 0.0F, 6, "otheraddr.b");
    const auto initial_b = connection.take_frames();
    REQUIRE(initial_b.size() == 3);
    const auto opened_b =
        sv2::decode_open_extended_mining_channel_success(initial_b[0].payload);

    pool.job->set_publication_sequence(2);
    session.publish_job(*pool.job, false);
    const auto published = connection.take_frames();
    REQUIRE(published.size() == 2);
    const auto job_a =
        sv2::decode_new_extended_mining_job(published[0].payload);
    const auto job_b =
        sv2::decode_new_extended_mining_job(published[1].payload);
    CHECK(job_a.channel_id == opened_a.channel_id);
    CHECK(job_b.channel_id == opened_b.channel_id);

    const util::uint256 harder_target =
        util::target_from_difficulty(
            util::difficulty_from_target(
                util::uint256::from_le_bytes(opened_a.target)) *
            2.0);
    sv2::U256 wire_harder{};
    std::copy(harder_target.le_bytes().begin(), harder_target.le_bytes().end(),
              wire_harder.begin());
    session.handle_bytes(sv2::encode_message(
        sv2::UpdateChannel{opened_a.channel_id, 0.0F, wire_harder}));
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].message_type == sv2::SetTarget::kMessageType);
    CHECK(sv2::decode_set_target(frames[0].payload).channel_id ==
          opened_a.channel_id);

    session.handle_bytes(sv2::encode_message(
        sv2::CloseChannel{opened_a.channel_id, "done"}));
    CHECK_FALSE(session.should_close());
    CHECK(session.authorized());
    auto stats = session.stats();
    CHECK(stats.channels.size() == 1);
    CHECK(stats.address == "otheraddr");
    CHECK(stats.worker == "b");

    session.handle_bytes(sv2::encode_message(
        sv2::UpdateChannel{opened_a.channel_id, 0.0F, maximum_target()}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(sv2::decode_update_channel_error(frames[0].payload).error_code ==
          "invalid-channel");

    const Bytes extranonce(opened_b.extranonce_size);
    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesExtended{
        opened_a.channel_id, 1, job_a.job_id, 0, now, pool.job->version(),
        extranonce}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(sv2::decode_submit_shares_error(frames[0].payload).error_code ==
          "invalid-channel");

    const stratum::ExtendedWork work =
        pool.job->build_extended_work(kPayoutScript);
    const util::uint256 target_b =
        util::uint256::from_le_bytes(opened_b.target);
    std::optional<uint32_t> valid_nonce;
    for (uint32_t nonce = 0; nonce < 4'096; ++nonce) {
        const auto result = pool.job->validate_extended_share(
            work, {opened_b.extranonce_prefix, extranonce,
                   opened_b.extranonce_size, now, nonce, pool.job->version(),
                   pool.version_mask(), target_b,
                   static_cast<int64_t>(std::time(nullptr))});
        if (result) {
            valid_nonce = nonce;
            break;
        }
    }
    REQUIRE(valid_nonce.has_value());
    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesExtended{
        opened_b.channel_id, 2, job_b.job_id, *valid_nonce, now,
        pool.job->version(), extranonce}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);
    stats = session.stats();
    REQUIRE(stats.channels.size() == 1);
    CHECK(stats.channels[0].address == "otheraddr");
    CHECK(stats.channels[0].shares_accepted == 1);
    CHECK(stats.channels[0].shares_rejected == 0);

    open_extended_channel(session, 9, 0.0F, 6, "validaddr.c");
    frames = connection.take_frames();
    REQUIRE(frames.size() == 3);
    const auto opened_c =
        sv2::decode_open_extended_mining_channel_success(frames[0].payload);
    CHECK(opened_c.channel_id == 3);
    CHECK(opened_c.extranonce_prefix.back() == 3);
}

TEST_CASE("SV2 closes every member of group zero without closing the connection") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.extranonce_size = 8;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    open_extended_channel(session, 7, 0.0F, 6, "validaddr.a");
    connection.take_frames();
    open_extended_channel(session, 8, 0.0F, 6, "otheraddr.b");
    connection.take_frames();
    REQUIRE(session.stats().channels.size() == 2);

    session.handle_bytes(
        sv2::encode_message(sv2::CloseChannel{0, "proxy-stopped"}));

    CHECK(session.stats().channels.empty());
    CHECK_FALSE(session.authorized());
    CHECK(session.ever_authorized());
    CHECK_FALSE(session.should_close());

    open_extended_channel(session, 9, 0.0F, 6, "validaddr.c");
    const auto frames = connection.take_frames();
    REQUIRE(frames.size() == 3);
    CHECK(sv2::decode_open_extended_mining_channel_success(frames[0].payload)
              .channel_id == 3);
}

TEST_CASE("SV2 keeps duplicate history when another channel opens clean work") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.extranonce_size = 8;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    open_extended_channel(session, 7, 0.0F, 6, "validaddr.a");
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_extended_mining_channel_success(initial[0].payload);
    const auto job =
        sv2::decode_new_extended_mining_job(initial[1].payload);
    const stratum::ExtendedWork work =
        pool.job->build_extended_work(kPayoutScript);
    const Bytes extranonce(opened.extranonce_size);
    const util::uint256 target =
        util::uint256::from_le_bytes(opened.target);

    std::optional<uint32_t> valid_nonce;
    for (uint32_t nonce = 0; nonce < 4'096; ++nonce) {
        const auto result = pool.job->validate_extended_share(
            work, {opened.extranonce_prefix, extranonce,
                   opened.extranonce_size, now, nonce, pool.job->version(),
                   pool.version_mask(), target,
                   static_cast<int64_t>(std::time(nullptr))});
        if (result) {
            valid_nonce = nonce;
            break;
        }
    }
    REQUIRE(valid_nonce.has_value());

    sv2::SubmitSharesExtended share{
        opened.channel_id, 1, job.job_id, *valid_nonce, now,
        pool.job->version(), extranonce};
    session.handle_bytes(sv2::encode_message(share));
    const auto accepted = connection.take_frames();
    REQUIRE(accepted.size() == 1);
    CHECK(accepted[0].message_type == sv2::SubmitSharesSuccess::kMessageType);

    open_extended_channel(session, 8, 0.0F, 6, "validaddr.b");
    REQUIRE(connection.take_frames().size() == 3);

    share.sequence_number = 2;
    session.handle_bytes(sv2::encode_message(share));
    const auto duplicate = connection.take_frames();
    REQUIRE(duplicate.size() == 1);
    CHECK(sv2::decode_submit_shares_error(duplicate[0].payload).error_code ==
          "duplicate-share");
}

TEST_CASE("SV2 enforces Extended Channel setup and extranonce requirements") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));

    SUBCASE("a Standard-only setup cannot open an Extended Channel") {
        FakePool pool(now);
        FakeConnection connection;
        sv2::Session session(pool, connection, util::from_hex("01020304"));

        setup(session);
        connection.take_frames();
        open_extended_channel(session);
        const auto frames = connection.take_frames();
        REQUIRE(frames.size() == 1);
        CHECK(sv2::decode_open_mining_channel_error(frames[0].payload).error_code ==
              "requires-standard-jobs");
        CHECK_FALSE(session.authorized());
    }

    SUBCASE("the requested extranonce must fit the configured space") {
        FakePool pool(now);
        pool.extranonce_size = 4;
        FakeConnection connection;
        sv2::Session session(pool, connection, util::from_hex("01020304"));

        setup(session, sv2::kSetupFlagRequiresVersionRolling);
        connection.take_frames();
        open_extended_channel(session, 7, 1.0F, 4);
        const auto frames = connection.take_frames();
        REQUIRE(frames.size() == 1);
        CHECK(sv2::decode_open_mining_channel_error(frames[0].payload).error_code ==
              "insufficient-extranonce-size");
        CHECK_FALSE(session.authorized());
    }

    SUBCASE("a channel discriminator must fit in the configured space") {
        FakePool pool(now);
        pool.extranonce_size = 0;
        FakeConnection connection;
        sv2::Session session(pool, connection, util::from_hex("01020304"));

        setup(session, sv2::kSetupFlagRequiresVersionRolling);
        connection.take_frames();
        open_extended_channel(session, 7, 0.0F, 0);
        const auto frames = connection.take_frames();
        REQUIRE(frames.size() == 1);
        CHECK(sv2::decode_open_mining_channel_error(frames[0].payload).error_code ==
              "insufficient-extranonce-size");
        CHECK_FALSE(session.authorized());
    }

    SUBCASE("hashrate cannot exhaust the full Extended space within one second") {
        FakePool pool(now);
        FakeConnection connection;
        sv2::Session session(pool, connection, util::from_hex("01020304"));

        setup(session, sv2::kSetupFlagRequiresVersionRolling);
        connection.take_frames();
        open_extended_channel(
            session, 7, std::numeric_limits<float>::max());
        const auto frames = connection.take_frames();
        REQUIRE(frames.size() == 1);
        CHECK(sv2::decode_open_mining_channel_error(frames[0].payload).error_code ==
              "invalid-nominal-hash-rate");
        CHECK_FALSE(session.authorized());
    }
}

TEST_CASE("SV2 channel IDs and prefixes cross the one-byte boundary without reuse") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.extranonce_size = 8;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    for (uint32_t expected_id = 1; expected_id <= 255; ++expected_id) {
        open_extended_channel(session, expected_id, 0.0F, 6);
        const auto frames = connection.take_frames();
        REQUIRE(frames.size() == 3);
        CHECK(sv2::decode_open_extended_mining_channel_success(frames[0].payload)
                  .channel_id == expected_id);
    }
    CHECK(session.stats().channels.size() == 255);

    open_extended_channel(session, 256, 0.0F, 6);
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(sv2::decode_open_mining_channel_error(frames[0].payload).error_code ==
          "channel-limit-reached");

    session.handle_bytes(
        sv2::encode_message(sv2::CloseChannel{1, "done"}));
    CHECK(session.stats().channels.size() == 254);
    open_extended_channel(session, 257, 0.0F, 6);
    frames = connection.take_frames();
    REQUIRE(frames.size() == 3);
    const auto opened =
        sv2::decode_open_extended_mining_channel_success(frames[0].payload);
    CHECK(opened.channel_id == 256);
    CHECK(opened.extranonce_prefix[opened.extranonce_prefix.size() - 2] == 1);
    CHECK(opened.extranonce_prefix.back() == 0);
}

TEST_CASE("SV2 rejects a Standard Channel until work is available") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.job.reset();
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    connection.take_frames();
    open_channel(session);
    const auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].message_type == sv2::OpenMiningChannelError::kMessageType);
    CHECK(sv2::decode_open_mining_channel_error(frames[0].payload).error_code ==
          "work-not-ready");
    CHECK_FALSE(session.authorized());
}

TEST_CASE("SV2 calibrates the initial target from nominal hashrate") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.job = make_job(now, "170fffff");
    pool.vardiff = true;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    connection.take_frames();
    constexpr float kNominalHashRate = 200'000'000'000'000.0F;
    open_channel(session, 7, kNominalHashRate);

    const auto frames = connection.take_frames();
    REQUIRE(frames.size() == 3);
    const auto opened =
        sv2::decode_open_standard_mining_channel_success(frames[0].payload);
    const double expected_difficulty =
        static_cast<double>(kNominalHashRate) * 60.0 /
        (stats::kHashesPerDiff1Share *
         pool.runtime_config()->vardiff_target_shares_per_minute);
    CHECK(util::uint256::from_le_bytes(opened.target) ==
          util::target_from_difficulty(expected_difficulty));
}

TEST_CASE("SV2 channel opens never assign a target harder than the network") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    for (const bool extended : {false, true}) {
        CAPTURE(extended);
        FakePool pool(now);
        pool.job = make_job(now, "207fffff");
        pool.initial_difficulty = 256.0;
        pool.minimum_difficulty = 128.0;
        pool.maximum_difficulty = 512.0;
        FakeConnection connection;
        sv2::Session session(pool, connection, util::from_hex("01020304"));
        setup(session, extended ? sv2::kSetupFlagRequiresVersionRolling
                                : sv2::kSetupFlagRequiresStandardJobs);
        connection.take_frames();
        if (extended)
            open_extended_channel(session);
        else
            open_channel(session);
        const auto frames = connection.take_frames();
        REQUIRE(frames.size() == 3);
        const sv2::U256 target = extended
                                    ? sv2::decode_open_extended_mining_channel_success(
                                          frames[0].payload).target
                                    : sv2::decode_open_standard_mining_channel_success(
                                          frames[0].payload).target;
        CHECK(util::uint256::from_le_bytes(target) == pool.job->network_target());
        CHECK(session.authorized());
        CHECK(session.protocol_errors() == 0);
    }
}

TEST_CASE("SV2 live difficulty bounds apply with VarDiff disabled") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.initial_difficulty = 0.25;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));
    setup(session);
    connection.take_frames();
    open_channel(session);
    connection.take_frames();

    pool.minimum_difficulty = 128.0;
    session.maybe_retarget();
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].message_type == sv2::SetTarget::kMessageType);
    CHECK(util::uint256::from_le_bytes(
              sv2::decode_set_target(frames[0].payload).maximum_target) ==
          pool.job->network_target());

    pool.minimum_difficulty = 0.125;
    pool.maximum_difficulty = 0.5;
    session.maybe_retarget();
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].message_type == sv2::SetTarget::kMessageType);
    CHECK(util::uint256::from_le_bytes(
              sv2::decode_set_target(frames[0].payload).maximum_target) ==
          util::target_from_difficulty(0.5));
    session.maybe_retarget();
    CHECK(connection.take_frames().empty());
}

TEST_CASE("SV2 nominal hashrate updates cannot exceed network difficulty") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.initial_difficulty = 0.25;
    pool.vardiff = true;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));
    setup(session);
    connection.take_frames();
    open_channel(session, 7, 0.0F);
    const auto initial = connection.take_frames();
    const auto opened = sv2::decode_open_standard_mining_channel_success(initial[0].payload);

    session.handle_bytes(sv2::encode_message(sv2::UpdateChannel{
        opened.channel_id, 200'000'000'000'000.0F, maximum_target()}));
    const auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].message_type == sv2::SetTarget::kMessageType);
    CHECK(util::uint256::from_le_bytes(
              sv2::decode_set_target(frames[0].payload).maximum_target) ==
          pool.job->network_target());
}

TEST_CASE("SV2 announces the exact new network ceiling before replacement work") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    for (const bool extended : {false, true}) {
        CAPTURE(extended);
        FakePool pool(now);
        pool.job = make_job(now, "170fffff");
        pool.initial_difficulty = 256.0;
        FakeConnection connection;
        sv2::Session session(pool, connection, util::from_hex("01020304"));
        setup(session, extended ? sv2::kSetupFlagRequiresVersionRolling
                                : sv2::kSetupFlagRequiresStandardJobs);
        connection.take_frames();
        if (extended)
            open_extended_channel(session);
        else
            open_channel(session);
        connection.take_frames();

        pool.job = make_job(now, "207fffff");
        session.publish_job(*pool.job, true);
        const auto frames = connection.take_frames();
        REQUIRE(frames.size() == (extended ? 3 : 4));
        REQUIRE(frames[0].message_type == sv2::SetTarget::kMessageType);
        CHECK(util::uint256::from_le_bytes(
                  sv2::decode_set_target(frames[0].payload).maximum_target) ==
              pool.job->network_target());
        CHECK(frames[frames.size() - 2].message_type ==
              (extended ? sv2::NewExtendedMiningJob::kMessageType
                        : sv2::NewMiningJob::kMessageType));
        CHECK(frames.back().message_type == sv2::SetNewPrevHash::kMessageType);
    }
}

TEST_CASE("SV2 uses the advertised job ceiling rather than a newer unpublished template") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.job = make_job(now, "207fffff");
    pool.initial_difficulty = 256.0;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));
    setup(session);
    connection.take_frames();
    open_channel(session);
    connection.take_frames();

    pool.retained_job = pool.job;
    pool.job = make_job(now, "170fffff");
    pool.minimum_difficulty = 128.0;
    session.maybe_retarget();
    CHECK(connection.take_frames().empty());
    session.publish_job(*pool.retained_job, false);
    const auto frames = connection.take_frames();
    REQUIRE(frames.size() == 2);
    CHECK(frames[0].message_type == sv2::SetExtranoncePrefix::kMessageType);
    CHECK(frames[1].message_type == sv2::NewMiningJob::kMessageType);
    CHECK(session.stats().difficulty ==
          util::difficulty_from_target(pool.retained_job->network_target()));
}

TEST_CASE("SV2 refuses incompatible device targets without closing the transport") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.initial_difficulty = 0.25;
    const sv2::U256 incompatible_target = util::target_from_difficulty(2.0).le_bytes();
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));
    setup(session);
    connection.take_frames();
    session.handle_bytes(sv2::encode_message(sv2::OpenStandardMiningChannel{
        7, "validaddr.rig", 0.0F, incompatible_target}));
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].message_type == sv2::OpenMiningChannelError::kMessageType);
    CHECK(sv2::decode_open_mining_channel_error(frames[0].payload).error_code ==
          "unsupported-target");
    CHECK_FALSE(session.authorized());
    CHECK_FALSE(session.should_close());
    CHECK(session.protocol_errors() == 0);

    open_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened = sv2::decode_open_standard_mining_channel_success(initial[0].payload);
    session.handle_bytes(sv2::encode_message(sv2::UpdateChannel{
        opened.channel_id, 0.0F, incompatible_target}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].message_type == sv2::UpdateChannelError::kMessageType);
    CHECK(sv2::decode_update_channel_error(frames[0].payload).error_code ==
          "unsupported-target");
    CHECK(session.stats().difficulty == util::difficulty_from_target(
              util::uint256::from_le_bytes(opened.target)));
    CHECK(session.authorized());
    CHECK_FALSE(session.should_close());
    CHECK(session.protocol_errors() == 0);
}

TEST_CASE("SV2 closes only incompatible channels when the network target becomes easier") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    const sv2::U256 device_target = util::target_from_difficulty(0.5).le_bytes();
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));
    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    session.handle_bytes(sv2::encode_message(sv2::OpenExtendedMiningChannel{
        7, "validaddr.a", 0.0F, device_target, 6}));
    const auto first = connection.take_frames();
    REQUIRE(first.size() == 3);
    const auto restricted = sv2::decode_open_extended_mining_channel_success(first[0].payload);
    open_extended_channel(session, 8, 0.0F, 6, "otheraddr.b");
    connection.take_frames();

    pool.job = make_job(now, "207fffff");
    session.publish_job(*pool.job, true);
    const auto frames = connection.take_frames();
    REQUIRE(frames.size() == 4);
    REQUIRE(frames[0].message_type == sv2::CloseChannel::kMessageType);
    const auto closed = sv2::decode_close_channel(frames[0].payload);
    CHECK(closed.channel_id == restricted.channel_id);
    CHECK(closed.reason_code == "unsupported-target");
    CHECK(frames[1].message_type == sv2::SetTarget::kMessageType);
    CHECK(frames[2].message_type == sv2::NewExtendedMiningJob::kMessageType);
    CHECK(frames[3].message_type == sv2::SetNewPrevHash::kMessageType);
    const auto snapshot = session.stats();
    REQUIRE(snapshot.channels.size() == 1);
    CHECK(snapshot.channels[0].worker == "b");
    CHECK(session.authorized());
    CHECK_FALSE(session.should_close());
    CHECK(session.protocol_errors() == 0);
}

TEST_CASE("SV2 retargets every open Extended Channel") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.extranonce_size = 8;
    pool.initial_difficulty = 1.0;
    pool.vardiff = true;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    open_extended_channel(session, 7, 0.0F, 6, "validaddr.a");
    connection.take_frames();
    open_extended_channel(session, 8, 0.0F, 6, "validaddr.b");
    connection.take_frames();

    session.maybe_retarget();
    const auto frames = connection.take_frames();
    REQUIRE(frames.size() == 2);
    REQUIRE(frames[0].message_type == sv2::SetTarget::kMessageType);
    REQUIRE(frames[1].message_type == sv2::SetTarget::kMessageType);
    CHECK(sv2::decode_set_target(frames[0].payload).channel_id == 1);
    CHECK(sv2::decode_set_target(frames[1].payload).channel_id == 2);
}

TEST_CASE("SV2 replenishes work for a high-hash Standard Channel") {
    constexpr float kHashRateRequiringFrequentRefresh =
        100'000'000'000'000'000.0F;
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    connection.take_frames();
    open_channel(session, 7, kHashRateRequiringFrequentRefresh);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto initial_job = sv2::decode_new_mining_job(initial[1].payload);

    session.maybe_refresh_job();

    const auto refreshed = connection.take_frames();
    REQUIRE(refreshed.size() == 2);
    CHECK(refreshed[0].message_type == sv2::SetExtranoncePrefix::kMessageType);
    CHECK(refreshed[1].message_type == sv2::NewMiningJob::kMessageType);
    const auto refreshed_job = sv2::decode_new_mining_job(refreshed[1].payload);
    CHECK(refreshed_job.minimum_ntime.has_value());
    CHECK(refreshed_job.merkle_root != initial_job.merkle_root);
}

TEST_CASE("SV2 immediately replaces work when an update enables rapid refresh") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    connection.take_frames();
    open_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_standard_mining_channel_success(initial[0].payload);
    const auto initial_job = sv2::decode_new_mining_job(initial[1].payload);

    session.handle_bytes(sv2::encode_message(sv2::UpdateChannel{
        opened.channel_id, 100'000'000'000'000'000.0F, maximum_target()}));
    const auto updated = connection.take_frames();
    REQUIRE(updated.size() == 2);
    CHECK(updated[0].message_type == sv2::SetExtranoncePrefix::kMessageType);
    REQUIRE(updated[1].message_type == sv2::NewMiningJob::kMessageType);
    CHECK(sv2::decode_new_mining_job(updated[1].payload).merkle_root !=
          initial_job.merkle_root);

    session.handle_bytes(sv2::encode_message(sv2::UpdateChannel{
        opened.channel_id, 100'000'000'000'000'000.0F, maximum_target()}));
    CHECK(connection.take_frames().empty());
}

TEST_CASE("SV2 honors a stricter device target update and can reopen after close") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    connection.take_frames();
    open_channel(session);
    const auto initial = connection.take_frames();
    const auto opened =
        sv2::decode_open_standard_mining_channel_success(initial[0].payload);
    const util::uint256 old_target =
        util::uint256::from_le_bytes(opened.target);
    const util::uint256 harder_target =
        util::target_from_difficulty(util::difficulty_from_target(old_target) * 2.0);
    sv2::U256 wire_harder{};
    std::copy(harder_target.le_bytes().begin(), harder_target.le_bytes().end(),
              wire_harder.begin());
    pool.job->set_publication_sequence(2);

    session.handle_bytes(sv2::encode_message(
        sv2::UpdateChannel{opened.channel_id, 2.0F, wire_harder}));
    const auto updated = connection.take_frames();
    REQUIRE(updated.size() == 1);
    CHECK(updated[0].message_type == sv2::SetTarget::kMessageType);
    CHECK(util::uint256::from_le_bytes(
              sv2::decode_set_target(updated[0].payload).maximum_target) ==
          harder_target);

    session.publish_job(*pool.job, true);
    const auto published = connection.take_frames();
    CHECK(std::ranges::count(
              published, sv2::NewMiningJob::kMessageType,
              &sv2::Frame::message_type) == 1);

    session.handle_bytes(sv2::encode_message(
        sv2::CloseChannel{opened.channel_id, "done"}));
    CHECK(connection.take_frames().empty());
    CHECK_FALSE(session.should_close());
    CHECK_FALSE(session.authorized());
    CHECK(session.ever_authorized());

    open_channel(session, 8);
    const auto reopened_frames = connection.take_frames();
    REQUIRE(reopened_frames.size() == 3);
    CHECK(sv2::decode_open_standard_mining_channel_success(reopened_frames[0].payload)
              .channel_id == 2);
    CHECK(session.authorized());
}

TEST_CASE("SV2 keeps an issued job's target immutable across vardiff") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    connection.take_frames();
    open_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto open =
        sv2::decode_open_standard_mining_channel_success(initial[0].payload);
    const auto future_job = sv2::decode_new_mining_job(initial[1].payload);
    const util::uint256 old_target =
        util::uint256::from_le_bytes(open.target);
    const stratum::StandardWork future_work =
        pool.job->build_standard_work(kPayoutScript, open.extranonce_prefix);

    session.publish_job(*pool.job, false);
    const auto active_frames = connection.take_frames();
    REQUIRE(active_frames.size() == 2);
    REQUIRE(active_frames[0].message_type ==
            sv2::SetExtranoncePrefix::kMessageType);
    const auto prefix =
        sv2::decode_set_extranonce_prefix(active_frames[0].payload);
    const auto active_job = sv2::decode_new_mining_job(active_frames[1].payload);
    const stratum::StandardWork active_work = pool.job->build_standard_work(
        kPayoutScript, prefix.extranonce_prefix);

    pool.vardiff = true;
    const util::uint256 expected_new_target =
        util::target_from_difficulty(util::difficulty_from_target(old_target) * 2.0);
    const auto active_candidates =
        find_old_only_shares(*pool.job, active_work, old_target, expected_new_target, 2);
    const auto future_candidates =
        find_old_only_shares(*pool.job, future_work, old_target, expected_new_target, 1);
    REQUIRE(active_candidates.size() == 2);
    REQUIRE(future_candidates.size() == 1);

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesStandard{
        open.channel_id, 1, active_job.job_id, active_candidates[0],
        pool.job->curtime(), pool.job->version()}));
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);

    session.maybe_retarget();
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].message_type == sv2::SetTarget::kMessageType);
    const util::uint256 new_target =
        util::uint256::from_le_bytes(sv2::decode_set_target(frames[0].payload).maximum_target);
    CHECK(new_target < old_target);

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesStandard{
        open.channel_id, 2, active_job.job_id, active_candidates[1],
        pool.job->curtime(), pool.job->version()}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);
    CHECK(pool.accepted == 2);

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesStandard{
        open.channel_id, 3, future_job.job_id, future_candidates[0],
        pool.job->curtime(), pool.job->version()}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesError::kMessageType);
    CHECK(pool.accepted == 2);
}

TEST_CASE("SV2 share accounting does not hold the session mutex") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    connection.take_frames();
    open_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_standard_mining_channel_success(initial[0].payload);
    const auto announced = sv2::decode_new_mining_job(initial[1].payload);
    const stratum::StandardWork work =
        pool.job->build_standard_work(kPayoutScript, opened.extranonce_prefix);
    const util::uint256 target = util::uint256::from_le_bytes(opened.target);
    std::optional<uint32_t> accepted_nonce;
    for (uint32_t nonce = 0; nonce < 4'096; ++nonce) {
        if (pool.job->validate_standard_share(
                {work.legacy_coinbase, work.merkle_root, now, nonce,
                 pool.job->version(), pool.version_mask(), target,
                 static_cast<int64_t>(std::time(nullptr))})) {
            accepted_nonce = nonce;
            break;
        }
    }
    REQUIRE(accepted_nonce.has_value());

    pool.pause_next_accepted.store(true, std::memory_order_relaxed);
    std::jthread submitter([&] {
        session.handle_bytes(sv2::encode_message(sv2::SubmitSharesStandard{
            opened.channel_id, 1, announced.job_id, *accepted_nonce, now,
            pool.job->version()}));
    });
    CHECK(pool.accepted_entered.try_acquire_for(std::chrono::seconds(1)));

    auto stats = std::async(std::launch::async, [&] { return session.stats(); });
    const bool stats_ready =
        stats.wait_for(std::chrono::milliseconds(100)) == std::future_status::ready;
    pool.accepted_release.release();
    submitter.join();

    CHECK(stats_ready);
    (void)stats.get();
    CHECK(session.stats().shares_accepted == 1);
    const auto response = connection.take_frames();
    REQUIRE(response.size() == 1);
    CHECK(response[0].message_type == sv2::SubmitSharesSuccess::kMessageType);
}

TEST_CASE("SV2 hands off a block once and rejects its duplicate") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.job = make_job(now, "207fffff");
    pool.initial_difficulty = 2.5;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    connection.take_frames();
    open_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_standard_mining_channel_success(initial[0].payload);
    const auto announced = sv2::decode_new_mining_job(initial[1].payload);
    const stratum::StandardWork work =
        pool.job->build_standard_work(kPayoutScript, opened.extranonce_prefix);
    const util::uint256 target = util::uint256::from_le_bytes(opened.target);

    std::optional<uint32_t> winning_nonce;
    for (uint32_t nonce = 0; nonce < 1'000; ++nonce) {
        const auto result = pool.job->validate_standard_share(
            {work.legacy_coinbase, work.merkle_root, pool.job->curtime(), nonce,
             pool.job->version(), pool.version_mask(), target,
             static_cast<int64_t>(std::time(nullptr))});
        if (result && result->is_block) {
            winning_nonce = nonce;
            break;
        }
    }
    REQUIRE(winning_nonce.has_value());

    sv2::SubmitSharesStandard share{
        opened.channel_id, 3, announced.job_id, *winning_nonce,
        pool.job->curtime(), pool.job->version()};
    session.handle_bytes(sv2::encode_message(share));
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);
    CHECK(sv2::decode_submit_shares_success(frames[0].payload)
              .new_shares_sum == 1);
    CHECK(pool.accepted == 1);
    CHECK(pool.blocks == 1);
    CHECK(pool.block_address == "validaddr");
    CHECK(pool.block_worker == "rig");
    CHECK(pool.block_job == pool.job.get());
    REQUIRE(pool.block_result.has_value());
    CHECK(pool.block_result->legacy_coinbase == work.legacy_coinbase);

    share.sequence_number = 4;
    session.handle_bytes(sv2::encode_message(share));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].message_type == sv2::SubmitSharesError::kMessageType);
    CHECK(sv2::decode_submit_shares_error(frames[0].payload).error_code ==
          "duplicate-share");
    CHECK(pool.accepted == 1);
    CHECK(pool.rejected == 1);
    CHECK(pool.blocks == 1);
}

TEST_CASE("SV2 accepts a block that rolls BIP323 general-purpose version bits") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.job = make_job(now, "207fffff");
    pool.initial_difficulty = 2.5;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    connection.take_frames();
    open_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_standard_mining_channel_success(initial[0].payload);
    const auto announced = sv2::decode_new_mining_job(initial[1].payload);
    const stratum::StandardWork work =
        pool.job->build_standard_work(kPayoutScript, opened.extranonce_prefix);
    const util::uint256 target = util::uint256::from_le_bytes(opened.target);

    // Bit 5 is general purpose under BIP323 but outside BIP320's 0x1fffe000.
    const uint32_t rolled_version = pool.job->version() ^ 0x00000020U;
    std::optional<uint32_t> winning_nonce;
    for (uint32_t nonce = 0; nonce < 1'000; ++nonce) {
        const auto result = pool.job->validate_standard_share(
            {work.legacy_coinbase, work.merkle_root, pool.job->curtime(), nonce, rolled_version,
             stratum::kSv2VersionRollingMask, target, static_cast<int64_t>(std::time(nullptr))});
        if (result && result->is_block) {
            winning_nonce = nonce;
            break;
        }
    }
    REQUIRE(winning_nonce.has_value());

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesStandard{
        opened.channel_id, 3, announced.job_id, *winning_nonce, pool.job->curtime(),
        rolled_version}));
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);
    CHECK(pool.blocks == 1);

    // Bits outside BIP323's general-purpose range stay fixed.
    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesStandard{
        opened.channel_id, 4, announced.job_id, *winning_nonce, pool.job->curtime(),
        pool.job->version() ^ 0x00000001U}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].message_type == sv2::SubmitSharesError::kMessageType);
    CHECK(sv2::decode_submit_shares_error(frames[0].payload).error_code == "invalid-share");
    CHECK(pool.blocks == 1);
}

TEST_CASE("SV2 hands off a block before closing on a later oversized frame") {
    constexpr uint32_t kMaximumPayloadSize = 256;
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.job = make_job(now, "207fffff");
    pool.initial_difficulty = 2.5;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"),
                         kMaximumPayloadSize);

    setup(session);
    connection.take_frames();
    open_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_standard_mining_channel_success(initial[0].payload);
    const auto announced = sv2::decode_new_mining_job(initial[1].payload);
    const stratum::StandardWork work =
        pool.job->build_standard_work(kPayoutScript, opened.extranonce_prefix);
    const util::uint256 target = util::uint256::from_le_bytes(opened.target);

    std::optional<uint32_t> winning_nonce;
    for (uint32_t nonce = 0; nonce < 1'000; ++nonce) {
        const auto result = pool.job->validate_standard_share(
            {work.legacy_coinbase, work.merkle_root, pool.job->curtime(), nonce,
             pool.job->version(), pool.version_mask(), target,
             static_cast<int64_t>(std::time(nullptr))});
        if (result && result->is_block) {
            winning_nonce = nonce;
            break;
        }
    }
    REQUIRE(winning_nonce.has_value());

    Bytes stream = sv2::encode_frame(sv2::Frame{1, 0x7f, {}});
    append(stream, sv2::encode_message(sv2::SubmitSharesStandard{
                       opened.channel_id, 3, announced.job_id, *winning_nonce,
                       pool.job->curtime(), pool.job->version()}));
    append(stream, Bytes{0x00, 0x00, 0x7f, 0x01, 0x01, 0x00});

    session.handle_bytes(stream);

    const auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);
    CHECK(pool.accepted == 1);
    CHECK(pool.blocks == 1);
    CHECK(session.should_close());
    CHECK(session.protocol_errors() == 1);
}

TEST_CASE("SV2 validates Extended shares and hands off the exact winning coinbase") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.job = make_job(now, "207fffff");
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    open_extended_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_extended_mining_channel_success(initial[0].payload);
    const auto announced =
        sv2::decode_new_extended_mining_job(initial[1].payload);
    const stratum::ExtendedWork work =
        pool.job->build_extended_work(kPayoutScript);
    const util::uint256 target = util::uint256::from_le_bytes(opened.target);
    Bytes extranonce(opened.extranonce_size);
    extranonce.back() = 1;

    std::optional<uint32_t> winning_nonce;
    Bytes winning_coinbase;
    for (uint32_t nonce = 0; nonce < 1'000; ++nonce) {
        const auto result = pool.job->validate_extended_share(
            work, {opened.extranonce_prefix, extranonce, opened.extranonce_size,
                   pool.job->curtime(), nonce, pool.job->version(),
                   pool.version_mask(), target,
                   static_cast<int64_t>(std::time(nullptr))});
        if (result && result->is_block) {
            winning_nonce = nonce;
            winning_coinbase = result->legacy_coinbase;
            break;
        }
    }
    REQUIRE(winning_nonce.has_value());

    sv2::SubmitSharesExtended share{
        opened.channel_id, 3, announced.job_id, *winning_nonce,
        pool.job->curtime(), pool.job->version(), extranonce};
    session.handle_bytes(sv2::encode_message(share));
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);
    CHECK(pool.accepted == 1);
    CHECK(pool.blocks == 1);
    CHECK(pool.block_address == "validaddr");
    CHECK(pool.block_worker == "rig");
    CHECK(pool.block_job == pool.job.get());
    REQUIRE(pool.block_result.has_value());
    CHECK(pool.block_result->legacy_coinbase == winning_coinbase);

    share.sequence_number = 4;
    session.handle_bytes(sv2::encode_message(share));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(sv2::decode_submit_shares_error(frames[0].payload).error_code ==
          "duplicate-share");
    CHECK(pool.accepted == 1);
    CHECK(pool.rejected == 1);
    CHECK(pool.blocks == 1);
}

TEST_CASE("SV2 Extended dedup includes extranonce and rejects the wrong size") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    open_extended_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_extended_mining_channel_success(initial[0].payload);
    const auto announced =
        sv2::decode_new_extended_mining_job(initial[1].payload);
    const stratum::ExtendedWork work =
        pool.job->build_extended_work(kPayoutScript);
    const util::uint256 target = util::uint256::from_le_bytes(opened.target);
    Bytes first_extranonce(opened.extranonce_size);
    first_extranonce.back() = 1;
    Bytes second_extranonce(opened.extranonce_size);
    second_extranonce.back() = 2;

    std::optional<uint32_t> shared_nonce;
    for (uint32_t nonce = 0; nonce < 4'096; ++nonce) {
        const auto first = pool.job->validate_extended_share(
            work, {opened.extranonce_prefix, first_extranonce,
                   opened.extranonce_size, pool.job->curtime(), nonce,
                   pool.job->version(), pool.version_mask(), target,
                   static_cast<int64_t>(std::time(nullptr))});
        const auto second = pool.job->validate_extended_share(
            work, {opened.extranonce_prefix, second_extranonce,
                   opened.extranonce_size, pool.job->curtime(), nonce,
                   pool.job->version(), pool.version_mask(), target,
                   static_cast<int64_t>(std::time(nullptr))});
        if (first && second) {
            shared_nonce = nonce;
            break;
        }
    }
    REQUIRE(shared_nonce.has_value());

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesExtended{
        opened.channel_id, 1, announced.job_id, *shared_nonce,
        pool.job->curtime(), pool.job->version(), first_extranonce}));
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesExtended{
        opened.channel_id, 2, announced.job_id, *shared_nonce,
        pool.job->curtime(), pool.job->version(), second_extranonce}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);
    CHECK(pool.accepted == 2);

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesExtended{
        opened.channel_id, 3, announced.job_id, 0, pool.job->curtime(),
        pool.job->version(), util::from_hex("0001")}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(sv2::decode_submit_shares_error(frames[0].payload).error_code ==
          "invalid-extranonce-size");
    CHECK(pool.rejected == 1);
}

TEST_CASE("SV2 invalidates old jobs when the previous hash changes") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    connection.take_frames();
    open_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_standard_mining_channel_success(initial[0].payload);
    const auto old_job = sv2::decode_new_mining_job(initial[1].payload);

    pool.job = make_job(now, "1d00ffff", std::string(63, '0') + "1");
    session.publish_job(*pool.job, true);
    const auto replacement = connection.take_frames();
    REQUIRE(replacement.size() == 3);

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesStandard{
        opened.channel_id, 5, old_job.job_id, 0, now, pool.job->version()}));
    const auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].message_type == sv2::SubmitSharesError::kMessageType);
    CHECK(sv2::decode_submit_shares_error(frames[0].payload).error_code ==
          "stale-share");
    CHECK(pool.accepted == 0);
    CHECK(pool.rejected == 1);
}

TEST_CASE("SV2 replaces the prevhash context when nBits changes on the same parent") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    connection.take_frames();
    open_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_standard_mining_channel_success(initial[0].payload);
    const auto old_job = sv2::decode_new_mining_job(initial[1].payload);

    pool.job = make_job(now, "1d00fffe");
    session.publish_job(*pool.job, false);
    const auto replacement = connection.take_frames();
    REQUIRE(replacement.size() == 3);
    REQUIRE(replacement[1].message_type == sv2::NewMiningJob::kMessageType);
    CHECK_FALSE(
        sv2::decode_new_mining_job(replacement[1].payload).minimum_ntime.has_value());
    REQUIRE(replacement[2].message_type == sv2::SetNewPrevHash::kMessageType);
    CHECK(sv2::decode_set_new_prev_hash(replacement[2].payload).nbits ==
          pool.job->bits());

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesStandard{
        opened.channel_id, 6, old_job.job_id, 0, now, pool.job->version()}));
    const auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(sv2::decode_submit_shares_error(frames[0].payload).error_code ==
          "stale-share");
}

TEST_CASE("SV2 keeps an active Extended job's target immutable across vardiff") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    open_extended_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_extended_mining_channel_success(initial[0].payload);
    const auto future_job =
        sv2::decode_new_extended_mining_job(initial[1].payload);
    const util::uint256 old_target =
        util::uint256::from_le_bytes(opened.target);
    const stratum::ExtendedWork work =
        pool.job->build_extended_work(kPayoutScript);
    Bytes extranonce(opened.extranonce_size);
    extranonce.back() = 1;

    session.publish_job(*pool.job, false);
    const auto active_frames = connection.take_frames();
    REQUIRE(active_frames.size() == 1);
    const auto active_job =
        sv2::decode_new_extended_mining_job(active_frames[0].payload);
    REQUIRE(active_job.minimum_ntime.has_value());

    pool.vardiff = true;
    const util::uint256 expected_new_target =
        util::target_from_difficulty(util::difficulty_from_target(old_target) * 2.0);
    const auto candidates =
        find_old_only_shares(*pool.job, work, opened.extranonce_prefix,
                             extranonce, old_target, expected_new_target, 3);
    REQUIRE(candidates.size() == 3);

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesExtended{
        opened.channel_id, 1, active_job.job_id, candidates[0],
        pool.job->curtime(), pool.job->version(), extranonce}));
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);

    session.maybe_retarget();
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].message_type == sv2::SetTarget::kMessageType);
    CHECK(util::uint256::from_le_bytes(
              sv2::decode_set_target(frames[0].payload).maximum_target) <
          old_target);
    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesExtended{
        opened.channel_id, 2, active_job.job_id, candidates[1],
        pool.job->curtime(), pool.job->version(), extranonce}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);
    CHECK(pool.accepted == 2);

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesExtended{
        opened.channel_id, 3, future_job.job_id, candidates[2],
        pool.job->curtime(), pool.job->version(), extranonce}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesError::kMessageType);
    CHECK(pool.accepted == 2);
}

TEST_CASE("SV2 Standard rejects nTime ahead of the latest prevhash window") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    connection.take_frames();
    open_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_standard_mining_channel_success(initial[0].payload);
    const auto job = sv2::decode_new_mining_job(initial[1].payload);
    const auto previous_hash =
        sv2::decode_set_new_prev_hash(initial[2].payload);

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesStandard{
        opened.channel_id, 20, job.job_id, 20,
        previous_hash.minimum_ntime + 60, pool.job->version()}));
    const auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(sv2::decode_submit_shares_error(frames[0].payload).error_code ==
          "invalid-ntime");
}

TEST_CASE("SV2 Extended enforces the announced nTime window") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.job = make_job(now, "207fffff");
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    open_extended_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_extended_mining_channel_success(initial[0].payload);

    pool.job = make_job(now - 1, "207fffff");
    session.publish_job(*pool.job, false);
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    const auto behind =
        sv2::decode_new_extended_mining_job(frames[0].payload);
    CHECK(behind.minimum_ntime == now);
    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesExtended{
        opened.channel_id, 21, behind.job_id, 21, now - 1,
        pool.job->version(), Bytes(opened.extranonce_size)}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(sv2::decode_submit_shares_error(frames[0].payload).error_code ==
          "invalid-ntime");

    pool.job = make_job(now + 10, "207fffff");
    session.publish_job(*pool.job, false);
    frames = connection.take_frames();
    REQUIRE(frames.size() == 2);
    const auto ahead =
        sv2::decode_new_extended_mining_job(frames[0].payload);
    CHECK_FALSE(ahead.minimum_ntime.has_value());
    REQUIRE(frames[1].message_type == sv2::SetNewPrevHash::kMessageType);
    CHECK(sv2::decode_set_new_prev_hash(frames[1].payload).minimum_ntime == now + 10);
    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesExtended{
        opened.channel_id, 22, ahead.job_id, 22, now + 60,
        pool.job->version(), Bytes(opened.extranonce_size)}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(sv2::decode_submit_shares_error(frames[0].payload).error_code ==
          "invalid-ntime");
}

TEST_CASE("SV2 Standard refreshes an aged channel's timestamp before issuing current work") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now - 30);
    pool.job = make_job(now - 30, "207fffff");
    pool.initial_difficulty = 2.5;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session);
    connection.take_frames();
    open_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_standard_mining_channel_success(initial[0].payload);
    CHECK(sv2::decode_set_new_prev_hash(initial[2].payload).minimum_ntime == now - 30);

    pool.job = make_job(now, "207fffff");
    session.publish_job(*pool.job, false);
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 3);
    REQUIRE(frames[0].message_type == sv2::SetExtranoncePrefix::kMessageType);
    REQUIRE(frames[1].message_type == sv2::NewMiningJob::kMessageType);
    REQUIRE(frames[2].message_type == sv2::SetNewPrevHash::kMessageType);
    const auto prefix = sv2::decode_set_extranonce_prefix(frames[0].payload);
    const auto announced = sv2::decode_new_mining_job(frames[1].payload);
    const auto previous_hash = sv2::decode_set_new_prev_hash(frames[2].payload);
    CHECK_FALSE(announced.minimum_ntime.has_value());
    CHECK(previous_hash.job_id == announced.job_id);
    CHECK(previous_hash.minimum_ntime == now);

    const auto work = pool.job->build_standard_work(kPayoutScript, prefix.extranonce_prefix);
    const auto target = util::uint256::from_le_bytes(opened.target);
    std::optional<uint32_t> winning_nonce;
    for (uint32_t nonce = 0; nonce < 1'000; ++nonce) {
        const auto result = pool.job->validate_standard_share(
            {work.legacy_coinbase, work.merkle_root, now, nonce,
             pool.job->version(), pool.version_mask(), target, now});
        if (result && result->is_block) {
            winning_nonce = nonce;
            break;
        }
    }
    REQUIRE(winning_nonce.has_value());
    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesStandard{
        opened.channel_id, 1, announced.job_id, *winning_nonce, now, pool.job->version()}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);
    CHECK(pool.blocks == 1);
    CHECK(pool.block_job == pool.job.get());
}

TEST_CASE("SV2 Extended refreshes an aged channel's timestamp before issuing current work") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now - 30);
    pool.job = make_job(now - 30, "207fffff");
    pool.initial_difficulty = 2.5;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    open_extended_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_extended_mining_channel_success(initial[0].payload);
    CHECK(sv2::decode_set_new_prev_hash(initial[2].payload).minimum_ntime == now - 30);

    pool.job = make_job(now, "207fffff");
    session.publish_job(*pool.job, false);
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 2);
    REQUIRE(frames[0].message_type == sv2::NewExtendedMiningJob::kMessageType);
    REQUIRE(frames[1].message_type == sv2::SetNewPrevHash::kMessageType);
    const auto announced = sv2::decode_new_extended_mining_job(frames[0].payload);
    const auto previous_hash = sv2::decode_set_new_prev_hash(frames[1].payload);
    CHECK_FALSE(announced.minimum_ntime.has_value());
    CHECK(previous_hash.job_id == announced.job_id);
    CHECK(previous_hash.minimum_ntime == now);

    const auto work = pool.job->build_extended_work(kPayoutScript);
    const Bytes extranonce(opened.extranonce_size);
    const auto target = util::uint256::from_le_bytes(opened.target);
    std::optional<uint32_t> winning_nonce;
    for (uint32_t nonce = 0; nonce < 1'000; ++nonce) {
        const auto result = pool.job->validate_extended_share(
            work, {opened.extranonce_prefix, extranonce, opened.extranonce_size,
                   now, nonce, pool.job->version(), pool.version_mask(), target, now});
        if (result && result->is_block) {
            winning_nonce = nonce;
            break;
        }
    }
    REQUIRE(winning_nonce.has_value());
    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesExtended{
        opened.channel_id, 1, announced.job_id, *winning_nonce, now,
        pool.job->version(), extranonce}));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);
    CHECK(pool.blocks == 1);
    CHECK(pool.block_job == pool.job.get());
}

TEST_CASE("SV2 retains late same-parent block solutions across clean work updates") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    pool.job = make_job(now, "207fffff");
    pool.initial_difficulty = 2.5;
    const auto original_job = pool.job;
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    open_extended_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_extended_mining_channel_success(initial[0].payload);
    const auto announced = sv2::decode_new_extended_mining_job(initial[1].payload);
    const auto work = original_job->build_extended_work(kPayoutScript);
    const Bytes extranonce(opened.extranonce_size);
    const auto target = util::uint256::from_le_bytes(opened.target);
    std::optional<uint32_t> winning_nonce;
    for (uint32_t nonce = 0; nonce < 1'000; ++nonce) {
        const auto result = original_job->validate_extended_share(
            work, {opened.extranonce_prefix, extranonce, opened.extranonce_size,
                   now, nonce, original_job->version(), pool.version_mask(), target, now});
        if (result && result->is_block) {
            winning_nonce = nonce;
            break;
        }
    }
    REQUIRE(winning_nonce.has_value());

    pool.job = make_job(now + 1, "207fffff");
    session.publish_job(*pool.job, true);
    auto frames = connection.take_frames();
    REQUIRE(frames.size() == 2);
    CHECK(sv2::decode_set_new_prev_hash(frames[1].payload).minimum_ntime == now + 1);

    sv2::SubmitSharesExtended share{
        opened.channel_id, 1, announced.job_id, *winning_nonce, now,
        original_job->version(), extranonce};
    session.handle_bytes(sv2::encode_message(share));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].message_type == sv2::SubmitSharesSuccess::kMessageType);
    CHECK(pool.blocks == 1);
    CHECK(pool.block_job == original_job.get());

    for (uint32_t offset = 2; offset <= 3; ++offset) {
        pool.job = make_job(now + offset, "207fffff");
        session.publish_job(*pool.job, true);
        REQUIRE(connection.take_frames().size() == 2);
    }
    share.sequence_number = 2;
    session.handle_bytes(sv2::encode_message(share));
    frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    REQUIRE(frames[0].message_type == sv2::SubmitSharesError::kMessageType);
    CHECK(sv2::decode_submit_shares_error(frames[0].payload).error_code == "duplicate-share");
    CHECK(pool.blocks == 1);
}

TEST_CASE("SV2 Extended replaces prevhash context when same-parent nBits changes") {
    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool(now);
    FakeConnection connection;
    sv2::Session session(pool, connection, util::from_hex("01020304"));

    setup(session, sv2::kSetupFlagRequiresVersionRolling);
    connection.take_frames();
    open_extended_channel(session);
    const auto initial = connection.take_frames();
    REQUIRE(initial.size() == 3);
    const auto opened =
        sv2::decode_open_extended_mining_channel_success(initial[0].payload);
    const auto old_job =
        sv2::decode_new_extended_mining_job(initial[1].payload);

    pool.job = make_job(now, "1d00fffe");
    session.publish_job(*pool.job, false);
    const auto replacement = connection.take_frames();
    REQUIRE(replacement.size() == 2);
    REQUIRE(replacement[0].message_type ==
            sv2::NewExtendedMiningJob::kMessageType);
    CHECK_FALSE(sv2::decode_new_extended_mining_job(replacement[0].payload)
                    .minimum_ntime.has_value());
    REQUIRE(replacement[1].message_type == sv2::SetNewPrevHash::kMessageType);
    CHECK(sv2::decode_set_new_prev_hash(replacement[1].payload).nbits ==
          pool.job->bits());

    session.handle_bytes(sv2::encode_message(sv2::SubmitSharesExtended{
        opened.channel_id, 6, old_job.job_id, 0, now, pool.job->version(),
        Bytes(opened.extranonce_size)}));
    const auto frames = connection.take_frames();
    REQUIRE(frames.size() == 1);
    CHECK(sv2::decode_submit_shares_error(frames[0].payload).error_code ==
          "stale-share");
}

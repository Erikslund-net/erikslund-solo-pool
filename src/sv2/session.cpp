#include "sv2/session.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <ctime>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>

#include "core/logging.hpp"
#include "util/checked_counter.hpp"
#include "util/difficulty.hpp"

namespace erikslund::sv2 {

namespace {

constexpr uint32_t kGroupChannelId = 0;
// Reserve two bytes for non-reused channel IDs; remaining extranonce bytes stay proxy-controlled.
constexpr std::size_t kChannelDiscriminatorBytes = 2;
constexpr uint32_t kMaximumChannelId =
    (uint32_t{1} << (8 * kChannelDiscriminatorBytes)) - 1;
constexpr std::size_t kMaximumActiveChannels = 255;
constexpr uint32_t kBip320VersionMask = 0x1fffe000;
constexpr std::size_t kMaximumIssuedJobs = 8;
constexpr double kNonceSpace = 4'294'967'296.0;
constexpr double kMaximumJobSpaceUtilization = 0.8;
constexpr double kJobRefreshSeconds =
    std::chrono::duration<double>(kStandardJobRefreshInterval).count();
log::RateLimit network_difficulty_warning_limit;
log::RateLimit incompatible_target_warning_limit;

util::uint256 bounded_target(const util::uint256& requested_target,
                             const util::uint256& device_maximum_target,
                             const RuntimeConfig& config,
                             const stratum::Job& job) {
    if (config.minimum_difficulty > job.maximum_share_difficulty())
        log::message_limited(log::Level::Warning, network_difficulty_warning_limit,
                             "SV2 minimum difficulty {} exceeds network difficulty {}; "
                             "using the network ceiling",
                             util::format_difficulty(config.minimum_difficulty),
                             util::format_difficulty(job.maximum_share_difficulty()));
    util::uint256 target =
        std::min(requested_target, util::target_from_difficulty(config.minimum_difficulty));
    if (config.maximum_difficulty > 0.0)
        target = std::max(target, util::target_from_difficulty(config.maximum_difficulty));
    return std::max(std::min(target, device_maximum_target), job.network_target());
}

template <typename Message>
void append_message(Bytes& destination, const Message& message) {
    append(destination, encode_message(message));
}

uint32_t maximum_ntime(uint32_t minimum_ntime, double started_at_steady,
                        double now_steady) {
    const double elapsed = std::max(0.0, now_steady - started_at_steady);
    const uint64_t maximum = static_cast<uint64_t>(minimum_ntime) +
                             static_cast<uint64_t>(elapsed);
    return static_cast<uint32_t>(std::min<uint64_t>(
        maximum, std::numeric_limits<uint32_t>::max()));
}

} // namespace

std::size_t Session::ShareKeyHash::operator()(const ShareKey& key) const noexcept {
    std::size_t value = key.channel_id;
    value = (value * 0x9e3779b1U) ^ key.job_id;
    value = (value * 0x9e3779b1U) ^ key.nonce;
    value = (value * 0x9e3779b1U) ^ key.ntime;
    value = (value * 0x9e3779b1U) ^ key.version;
    for (const uint8_t byte : key.extranonce)
        value = (value * 0x9e3779b1U) ^ byte;
    return value;
}

Session::Session(stratum::PoolContext& pool, Connection& connection, Bytes extranonce1,
                 uint32_t maximum_payload_size)
    : pool_(pool),
      connection_(connection),
      decoder_(maximum_payload_size),
      extranonce1_(std::move(extranonce1)),
      // SV2 has no mask negotiation, so an operator-narrowed SV1 mask means fixed-version SV2 work.
      version_mask_(pool.version_mask() == kBip320VersionMask ? stratum::kSv2VersionRollingMask
                                                              : 0),
      connected_at_(static_cast<int64_t>(std::time(nullptr))),
      connected_at_steady_(stats::steady_seconds()),
      hashrate_(std::span<const int, stats::kHashrateWindows.size()>(stats::kHashrateWindows),
                connected_at_steady_) {}

void Session::send_locked(ByteView bytes) {
    connection_.send_bytes(bytes);
}

double Session::job_hashes(ChannelKind kind) const {
    const std::size_t extranonce_bits =
        kind == ChannelKind::Extended &&
                pool_.extranonce2_size() >= kChannelDiscriminatorBytes
            ? (pool_.extranonce2_size() - kChannelDiscriminatorBytes) * 8
            : 0;
    const int exponent =
        static_cast<int>(std::popcount(version_mask_) + extranonce_bits);
    return std::ldexp(kNonceSpace, exponent);
}

double Session::maximum_hash_rate(ChannelKind kind) const {
    const double refresh_interval =
        kind == ChannelKind::Standard ? kJobRefreshSeconds : 1.0;
    return job_hashes(kind) * kMaximumJobSpaceUtilization / refresh_interval;
}

double Session::difficulty_for_hashrate(float nominal_hash_rate,
                                        const RuntimeConfig& config) const {
    double selected_difficulty =
        std::max(config.initial_difficulty, config.minimum_difficulty);
    if (config.variable_difficulty && nominal_hash_rate > 0.0F) {
        const double hashrate_difficulty =
            static_cast<double>(nominal_hash_rate) * 60.0 /
            (stats::kHashesPerDiff1Share * config.vardiff_target_shares_per_minute);
        selected_difficulty = std::max(selected_difficulty, hashrate_difficulty);
        const double maximum_difficulty = config.maximum_difficulty;
        if (maximum_difficulty > 0.0)
            selected_difficulty =
                std::min(selected_difficulty, maximum_difficulty);
    }
    return selected_difficulty;
}

void Session::update_job_refresh_requirement_locked(
    Channel& channel, float nominal_hash_rate) {
    channel.requires_frequent_job_refresh =
        channel.kind == ChannelKind::Standard &&
        static_cast<double>(nominal_hash_rate) > job_hashes(ChannelKind::Standard);
}

Bytes Session::allocate_extranonce_prefix_locked() {
    const std::size_t suffix_size = pool_.extranonce2_size();
    if (extranonce_counter_ >= util::counter_maximum(suffix_size)) {
        close_after_response_ = true;
        throw std::overflow_error("SV2 extranonce space exhausted; reconnect required");
    }
    ++extranonce_counter_;
    Bytes prefix = extranonce1_;
    prefix.resize(prefix.size() + suffix_size);
    for (std::size_t index = 0; index < suffix_size; ++index)
        prefix[prefix.size() - 1 - index] =
            static_cast<uint8_t>(extranonce_counter_ >> (8 * index));
    return prefix;
}

uint32_t Session::allocate_job_id_locked() {
    if (next_job_id_ == 0) {
        close_after_response_ = true;
        throw std::overflow_error("SV2 job IDs exhausted; reconnect required");
    }
    return next_job_id_++;
}

void Session::rotate_share_history_for_clean_job_locked(
    const std::shared_ptr<const stratum::Job>& job) {
    if (last_clean_job_.lock() == job &&
        last_clean_publication_sequence_ == job->publication_sequence())
        return;

    last_clean_job_ = job;
    last_clean_publication_sequence_ = job->publication_sequence();
    if (!seen_shares_.empty()) {
        seen_shares_previous_ = std::move(seen_shares_);
        seen_shares_.clear();
    }
}

void Session::handle_bytes(ByteView bytes) {
    std::vector<FoundBlock> found_blocks;
    {
        std::unique_lock lock(mutex_);
        std::vector<Frame> frames;
        std::optional<std::string> trailing_codec_error;
        try {
            frames = decoder_.push(bytes);
        } catch (CodecError& error) {
            trailing_codec_error = error.what();
            frames = error.take_completed_frames();
        } catch (const std::exception& error) {
            ++protocol_errors_;
            close_after_response_ = true;
            log::warning("SV2 handler error from {}: {}", connection_.peer(), error.what());
        }

        bool dispatch_failed = false;
        try {
            for (const Frame& frame : frames) {
                dispatch_locked(frame, lock);
                if (close_after_response_)
                    break;
            }
        } catch (const CodecError& error) {
            dispatch_failed = true;
            ++protocol_errors_;
            close_after_response_ = true;
            log::debug("Malformed SV2 frame from {}: {}", connection_.peer(), error.what());
        } catch (const std::exception& error) {
            dispatch_failed = true;
            ++protocol_errors_;
            close_after_response_ = true;
            log::warning("SV2 handler error from {}: {}", connection_.peer(), error.what());
        }
        if (trailing_codec_error && !dispatch_failed) {
            ++protocol_errors_;
            close_after_response_ = true;
            log::debug("Malformed SV2 frame from {}: {}", connection_.peer(),
                       *trailing_codec_error);
        }
        found_blocks.swap(pending_blocks_);
    }
    // Deliver blocks outside the mutex so disk spooling cannot stall the connection.
    for (const FoundBlock& block : found_blocks) {
        pool_.on_block_found(block.address, block.worker,
                             *block.source_job,
                             block.result);
    }
}

void Session::dispatch_locked(const Frame& frame, std::unique_lock<std::mutex>& lock) {
    if (frame.extension_id() != kCoreExtensionId)
        return;

    if (!setup_complete_) {
        if (frame.message_type != SetupConnection::kMessageType || frame.is_channel_message()) {
            ++protocol_errors_;
            send_locked(encode_message(
                SetupConnectionError{0, "setup-connection-required"}));
            close_after_response_ = true;
            return;
        }
        handle_setup_locked(decode_setup_connection(frame.payload));
        return;
    }

    switch (frame.message_type) {
    case SetupConnection::kMessageType:
        ++protocol_errors_;
        send_locked(encode_message(
            SetupConnectionError{0, "setup-connection-already-complete"}));
        close_after_response_ = true;
        break;
    case OpenStandardMiningChannel::kMessageType:
        if (frame.is_channel_message())
            throw CodecError("OpenStandardMiningChannel has channel routing bit set");
        handle_open_locked(decode_open_standard_mining_channel(frame.payload));
        break;
    case OpenExtendedMiningChannel::kMessageType:
        if (frame.is_channel_message())
            throw CodecError("OpenExtendedMiningChannel has channel routing bit set");
        handle_open_locked(decode_open_extended_mining_channel(frame.payload));
        break;
    case UpdateChannel::kMessageType:
        if (!frame.is_channel_message())
            throw CodecError("UpdateChannel is missing channel routing bit");
        handle_update_locked(decode_update_channel(frame.payload));
        break;
    case CloseChannel::kMessageType:
        if (!frame.is_channel_message())
            throw CodecError("CloseChannel is missing channel routing bit");
        handle_close_locked(decode_close_channel(frame.payload));
        break;
    case SubmitSharesStandard::kMessageType:
        if (!frame.is_channel_message())
            throw CodecError("SubmitSharesStandard is missing channel routing bit");
        handle_submit_locked(decode_submit_shares_standard(frame.payload), lock);
        break;
    case SubmitSharesExtended::kMessageType:
        if (!frame.is_channel_message())
            throw CodecError("SubmitSharesExtended is missing channel routing bit");
        handle_submit_locked(decode_submit_shares_extended(frame.payload), lock);
        break;
    default:
        ++protocol_errors_;
        break;
    }
}

void Session::handle_setup_locked(const SetupConnection& message) {
    uint32_t supported_flags = kSetupFlagRequiresStandardJobs;
    if (version_mask_ != 0)
        supported_flags |= kSetupFlagRequiresVersionRolling;
    const uint32_t unsupported_flags = message.flags & ~supported_flags;
    if (message.protocol != kMiningProtocol) {
        send_locked(encode_message(SetupConnectionError{0, "unsupported-protocol"}));
        close_after_response_ = true;
        return;
    }
    if (message.minimum_version > kProtocolVersion ||
        message.maximum_version < kProtocolVersion) {
        send_locked(encode_message(
            SetupConnectionError{0, "protocol-version-mismatch"}));
        close_after_response_ = true;
        return;
    }
    if (unsupported_flags != 0) {
        send_locked(encode_message(
            SetupConnectionError{unsupported_flags, "unsupported-feature-flags"}));
        close_after_response_ = true;
        return;
    }

    setup_complete_ = true;
    requested_setup_flags_ = message.flags;
    std::string identity;
    for (const std::string* part : {&message.vendor, &message.hardware_version,
                                    &message.firmware}) {
        if (part->empty())
            continue;
        if (!identity.empty())
            identity.push_back('/');
        identity += *part;
    }
    user_agent_ = log::sanitize(identity);
    send_locked(encode_message(SetupConnectionSuccess{
        kProtocolVersion,
        version_mask_ == 0 ? kSetupSuccessFlagRequiresFixedVersion : 0}));
}

void Session::handle_open_locked(const OpenStandardMiningChannel& message) {
    open_channel_locked(message.request_id, message.user_identity,
                        message.nominal_hash_rate, message.maximum_target,
                        ChannelKind::Standard);
}

void Session::handle_open_locked(const OpenExtendedMiningChannel& message) {
    if ((requested_setup_flags_ & kSetupFlagRequiresStandardJobs) != 0) {
        ++protocol_errors_;
        send_locked(encode_message(
            OpenMiningChannelError{message.request_id, "requires-standard-jobs"}));
        return;
    }
    const std::size_t configured_size = pool_.extranonce2_size();
    if (configured_size < kChannelDiscriminatorBytes ||
        message.minimum_extranonce_size >
            configured_size - kChannelDiscriminatorBytes) {
        ++protocol_errors_;
        send_locked(encode_message(OpenMiningChannelError{
            message.request_id, "insufficient-extranonce-size"}));
        return;
    }
    open_channel_locked(message.request_id, message.user_identity,
                        message.nominal_hash_rate, message.maximum_target,
                        ChannelKind::Extended);
}

void Session::open_channel_locked(uint32_t request_id, std::string_view user_identity,
                                  float nominal_hash_rate,
                                  const U256& maximum_target_bytes,
                                  ChannelKind kind) {
    const bool standard_channel_is_open =
        std::ranges::any_of(channels_, [](const auto& entry) {
            return entry.second.kind == ChannelKind::Standard;
        });
    if (next_channel_id_ > kMaximumChannelId) {
        send_locked(encode_message(
            OpenMiningChannelError{request_id, "channel-limit-reached"}));
        close_after_response_ = true;
        return;
    }
    if ((kind == ChannelKind::Standard && !channels_.empty()) ||
        (kind == ChannelKind::Extended &&
         (standard_channel_is_open ||
          channels_.size() >= kMaximumActiveChannels))) {
        send_locked(encode_message(
            OpenMiningChannelError{request_id, "channel-limit-reached"}));
        return;
    }
    // Standard counters and Extended prefixes can overlap even after channels close.
    if (channel_kind_ && *channel_kind_ != kind) {
        send_locked(encode_message(
            OpenMiningChannelError{request_id, "channel-type-change-requires-reconnect"}));
        return;
    }
    if (!std::isfinite(nominal_hash_rate) || nominal_hash_rate < 0.0F ||
        static_cast<double>(nominal_hash_rate) > maximum_hash_rate(kind)) {
        ++protocol_errors_;
        send_locked(encode_message(
            OpenMiningChannelError{request_id, "invalid-nominal-hash-rate"}));
        return;
    }

    const util::uint256 maximum_target =
        util::uint256::from_le_bytes(maximum_target_bytes);
    if (maximum_target.is_zero()) {
        ++protocol_errors_;
        send_locked(encode_message(
            OpenMiningChannelError{request_id, "too-low-difficulty"}));
        return;
    }

    const std::string sanitized_identity = log::sanitize(user_identity);
    const std::size_t sanitized_separator = sanitized_identity.find('.');
    std::string address = sanitized_identity.substr(0, sanitized_separator);
    const std::size_t separator = user_identity.find('.');
    std::string worker =
        separator == std::string::npos
            ? std::string{}
            : log::ascii_only(user_identity.substr(separator + 1));
    auto payout_script = pool_.validate_address(address);
    if (!payout_script) {
        ++protocol_errors_;
        send_locked(encode_message(
            OpenMiningChannelError{request_id, "unknown-user"}));
        return;
    }

    const auto current_job = pool_.current_job();
    if (!current_job) {
        send_locked(encode_message(
            OpenMiningChannelError{request_id, "work-not-ready"}));
        return;
    }
    if (maximum_target < current_job->network_target()) {
        send_locked(encode_message(
            OpenMiningChannelError{request_id, "unsupported-target"}));
        log::message_limited(log::Level::Warning, incompatible_target_warning_limit,
                             "Refused SV2 channel for {}: device maximum target "
                             "is harder than the network target",
                             connection_.peer());
        return;
    }

    const uint32_t channel_id = next_channel_id_;
    Channel channel(channel_id, kind, stats::steady_seconds());
    channel.address = std::move(address);
    channel.worker = std::move(worker);
    channel.payout_script = std::move(*payout_script);
    channel.worker_accounting =
        pool_.attach_worker(channel.address, channel.worker);
    channel.device_maximum_target = maximum_target;
    const auto config = pool_.runtime_config();
    channel.target = bounded_target(
        util::target_from_difficulty(difficulty_for_hashrate(nominal_hash_rate, *config)),
        channel.device_maximum_target, *config, *current_job);
    channel.difficulty = util::difficulty_from_target(channel.target);
    channel.last_publication_sequence =
        current_job->publication_sequence();
    update_job_refresh_requirement_locked(channel, nominal_hash_rate);
    if (kind == ChannelKind::Extended) {
        channel.extranonce_prefix = extranonce1_;
        for (std::size_t index = 0; index < kChannelDiscriminatorBytes; ++index) {
            const std::size_t shift =
                8 * (kChannelDiscriminatorBytes - index - 1);
            channel.extranonce_prefix.push_back(
                static_cast<uint8_t>(channel_id >> shift));
        }
        channel.extranonce_size =
            pool_.extranonce2_size() - kChannelDiscriminatorBytes;
    }

    auto [channel_entry, inserted] =
        channels_.emplace(channel_id, std::move(channel));
    if (!inserted)
        throw std::logic_error("SV2 channel ID collision");
    Channel& opened_channel = channel_entry->second;
    ++next_channel_id_;
    channel_kind_ = kind;
    ever_authorized_ = true;

    if (kind == ChannelKind::Standard) {
        Bytes extranonce_prefix = allocate_extranonce_prefix_locked();
        send_locked(encode_message(OpenStandardMiningChannelSuccess{
            request_id, channel_id, opened_channel.target.le_bytes(),
            extranonce_prefix,
            kGroupChannelId}));
        issue_job_locked(opened_channel, current_job, true,
                         std::move(extranonce_prefix));
    } else {
        send_locked(encode_message(OpenExtendedMiningChannelSuccess{
            request_id, channel_id, opened_channel.target.le_bytes(),
            static_cast<uint16_t>(opened_channel.extranonce_size),
            opened_channel.extranonce_prefix,
            kGroupChannelId}));
        issue_job_locked(opened_channel, current_job, true);
    }
    log::info("Opened SV2 channel {} for {} (address={}, user_agent={})",
              channel_id, connection_.peer(), opened_channel.address,
              user_agent_);
}

void Session::handle_update_locked(const UpdateChannel& message) {
    const auto channel_entry = channels_.find(message.channel_id);
    if (channel_entry == channels_.end()) {
        ++protocol_errors_;
        send_locked(encode_message(
            UpdateChannelError{message.channel_id, "invalid-channel"}));
        return;
    }
    Channel& channel = channel_entry->second;
    if (!std::isfinite(message.nominal_hash_rate) || message.nominal_hash_rate < 0.0F ||
        static_cast<double>(message.nominal_hash_rate) >
            maximum_hash_rate(channel.kind)) {
        ++protocol_errors_;
        send_locked(encode_message(
            UpdateChannelError{message.channel_id, "invalid-nominal-hash-rate"}));
        return;
    }
    const util::uint256 maximum_target =
        util::uint256::from_le_bytes(message.maximum_target);
    if (maximum_target.is_zero()) {
        ++protocol_errors_;
        send_locked(encode_message(
            UpdateChannelError{message.channel_id, "too-low-difficulty"}));
        return;
    }
    if (channel.jobs.empty()) {
        send_locked(encode_message(
            UpdateChannelError{message.channel_id, "work-not-ready"}));
        return;
    }
    const auto source_job = channel.jobs.back().second->source_job;
    if (maximum_target < source_job->network_target()) {
        send_locked(encode_message(
            UpdateChannelError{message.channel_id, "unsupported-target"}));
        log::message_limited(log::Level::Warning, incompatible_target_warning_limit,
                             "Refused SV2 target update for {} channel {}: "
                             "device maximum target is harder than the network target",
                             connection_.peer(), channel.id);
        return;
    }
    const bool frequent_refresh_was_required =
        channel.requires_frequent_job_refresh;
    channel.device_maximum_target = maximum_target;
    update_job_refresh_requirement_locked(channel,
                                          message.nominal_hash_rate);
    util::uint256 requested_target = channel.target;
    const auto config = pool_.runtime_config();
    if (config->variable_difficulty && message.nominal_hash_rate > 0.0F) {
        requested_target = util::target_from_difficulty(
            difficulty_for_hashrate(message.nominal_hash_rate, *config));
    }
    requested_target = bounded_target(requested_target, channel.device_maximum_target,
                                      *config, *source_job);
    if (requested_target != channel.target) {
        change_target_locked(channel, requested_target);
    } else if (!frequent_refresh_was_required &&
               channel.requires_frequent_job_refresh) {
        if (const auto current_job = pool_.current_job())
            issue_job_locked(
                channel, current_job,
                requires_new_prevhash_locked(channel, *current_job));
    }
}

void Session::handle_close_locked(const CloseChannel& message) {
    if (message.channel_id == kGroupChannelId) {
        if (channels_.empty()) {
            ++protocol_errors_;
            return;
        }
        const std::size_t closed_channels = channels_.size();
        channels_.clear();
        log::info("Closed SV2 group {} for {} ({} channels)",
                  message.channel_id, connection_.peer(), closed_channels);
        return;
    }
    const auto channel_entry = channels_.find(message.channel_id);
    if (channel_entry == channels_.end()) {
        ++protocol_errors_;
        return;
    }
    log::info("Closed SV2 channel {} for {}", message.channel_id,
              connection_.peer());
    channels_.erase(channel_entry);
}

void Session::issue_job_locked(Channel& channel,
                               const std::shared_ptr<const stratum::Job>& job, bool clean,
                               std::optional<Bytes> announced_prefix) {
    JobBuildPlan plan =
        prepare_job_locked(channel, job, std::move(announced_prefix));
    build_job_work(plan);
    commit_job_locked(channel, std::move(plan), clean);
}

Session::JobBuildPlan Session::prepare_job_locked(
    Channel& channel, const std::shared_ptr<const stratum::Job>& job,
    std::optional<Bytes> announced_prefix) {
    JobBuildPlan plan;
    plan.channel_id = channel.id;
    plan.kind = channel.kind;
    plan.source_job = job;
    plan.payout_script = channel.payout_script;
    plan.job_id = allocate_job_id_locked();
    if (channel.kind == ChannelKind::Standard) {
        plan.extranonce_prefix =
            announced_prefix ? std::move(*announced_prefix)
                             : allocate_extranonce_prefix_locked();
        plan.announce_extranonce_prefix = !announced_prefix.has_value();
    } else {
        plan.extranonce_prefix = channel.extranonce_prefix;
        plan.extranonce_size = channel.extranonce_size;
    }
    return plan;
}

void Session::build_job_work(JobBuildPlan& plan) {
    if (plan.kind == ChannelKind::Standard) {
        plan.work = plan.source_job->build_standard_work(
            plan.payout_script, plan.extranonce_prefix);
    } else {
        plan.work =
            plan.source_job->build_extended_work(plan.payout_script);
    }
}

void Session::commit_job_locked(Channel& channel, JobBuildPlan&& plan, bool clean) {
    if (channel.device_maximum_target < plan.source_job->network_target()) {
        const uint32_t channel_id = channel.id;
        send_locked(encode_message(CloseChannel{channel_id, "unsupported-target"}));
        channels_.erase(channel_id);
        log::message_limited(log::Level::Warning, incompatible_target_warning_limit,
                             "Closed SV2 channel {} for {}: device maximum target "
                             "is harder than the new network target",
                             channel_id, connection_.peer());
        return;
    }
    const auto config = pool_.runtime_config();
    const util::uint256 target = bounded_target(
        channel.target, channel.device_maximum_target, *config, *plan.source_job);
    if (target != channel.target)
        change_target_locked(channel, target);
    const double now_steady = stats::steady_seconds();
    const bool new_prevhash = requires_new_prevhash_locked(channel, *plan.source_job);
    const bool clean_job = clean || new_prevhash ||
        plan.source_job->curtime() >
            maximum_ntime(channel.previous_hash_minimum_ntime,
                          channel.previous_hash_received_at_steady, now_steady);
    if (new_prevhash) {
        rotate_share_history_for_clean_job_locked(plan.source_job);
        channel.jobs.clear();
    }
    if (clean_job) {
        channel.previous_hash = plan.source_job->prevhash_internal();
        channel.previous_bits = plan.source_job->bits();
        channel.previous_hash_minimum_ntime = plan.source_job->curtime();
        channel.previous_hash_received_at_steady = now_steady;
    }
    const uint32_t job_minimum_ntime =
        std::max(plan.source_job->curtime(), channel.previous_hash_minimum_ntime);
    // Late same-parent shares retain the timestamp window they were issued with.
    auto issued = std::make_shared<IssuedJob>(
        IssuedJob{plan.source_job, std::move(plan.work),
                  std::move(plan.extranonce_prefix), plan.extranonce_size,
                  channel.target, job_minimum_ntime,
                  channel.previous_hash_minimum_ntime,
                  channel.previous_hash_received_at_steady, clean_job});
    const IssuedJob& issued_job = *issued;
    channel.jobs.emplace_back(plan.job_id, std::move(issued));
    while (channel.jobs.size() > kMaximumIssuedJobs)
        channel.jobs.pop_front();

    Bytes outbound;
    const std::optional<uint32_t> minimum_ntime =
        clean_job
            ? std::nullopt
            : std::optional<uint32_t>(job_minimum_ntime);
    if (channel.kind == ChannelKind::Standard) {
        const auto& standard = std::get<stratum::StandardWork>(issued_job.work);
        if (plan.announce_extranonce_prefix) {
            append_message(outbound, SetExtranoncePrefix{
                                         channel.id, issued_job.extranonce_prefix});
        }
        append_message(outbound, NewMiningJob{channel.id, plan.job_id, minimum_ntime,
                                              plan.source_job->version(),
                                              standard.merkle_root});
    } else {
        const auto& extended = std::get<stratum::ExtendedWork>(issued_job.work);
        append_message(
            outbound,
            NewExtendedMiningJob{channel.id, plan.job_id, minimum_ntime,
                                 plan.source_job->version(),
                                 version_mask_ != 0, extended.merkle_path,
                                 extended.coinbase_tx_prefix,
                                 extended.coinbase_tx_suffix});
    }
    if (clean_job) {
        U256 previous_hash{};
        std::copy(plan.source_job->prevhash_internal().begin(),
                  plan.source_job->prevhash_internal().end(),
                  previous_hash.begin());
        append_message(outbound, SetNewPrevHash{channel.id, plan.job_id, previous_hash,
                                                job_minimum_ntime,
                                                plan.source_job->bits()});
    }
    send_locked(outbound);
}

void Session::publish_job(const stratum::Job& job, bool clean) {
    auto published_job = pool_.recent_job(job.job_id());
    if (!published_job) {
        published_job = pool_.current_job();
        if (published_job && published_job->job_id() != job.job_id())
            published_job.reset();
    }
    if (!published_job)
        return;

    std::vector<JobBuildPlan> job_plans;
    try {
        {
            const std::scoped_lock lock(mutex_);
            if (channels_.empty())
                return;
            job_plans.reserve(channels_.size());
            const uint64_t publication_sequence =
                published_job->publication_sequence();
            for (auto& [channel_id, channel] : channels_) {
                (void)channel_id;
                if (publication_sequence != 0 &&
                    publication_sequence <=
                        channel.last_publication_sequence)
                    continue;
                job_plans.push_back(
                    prepare_job_locked(channel, published_job));
            }
        }

        for (JobBuildPlan& job_plan : job_plans) {
            build_job_work(job_plan);

            const std::scoped_lock lock(mutex_);
            const auto channel_entry = channels_.find(job_plan.channel_id);
            if (channel_entry == channels_.end())
                continue;
            Channel& channel = channel_entry->second;
            const uint64_t publication_sequence =
                published_job->publication_sequence();
            if (publication_sequence != 0 &&
                publication_sequence <= channel.last_publication_sequence)
                continue;
            channel.last_publication_sequence =
                std::max(channel.last_publication_sequence,
                         publication_sequence);
            commit_job_locked(channel, std::move(job_plan), clean);
        }
    } catch (const std::exception& error) {
        log::warning("Could not publish SV2 job to {}: {}", connection_.peer(), error.what());
    }
}

void Session::maybe_refresh_job() {
    const auto current_job = pool_.current_job();
    if (!current_job)
        return;

    std::optional<JobBuildPlan> job_plan;
    try {
        {
            const std::scoped_lock lock(mutex_);
            const auto standard_channel_entry =
                std::ranges::find_if(channels_, [](const auto& entry) {
                    return entry.second.kind == ChannelKind::Standard &&
                           entry.second.requires_frequent_job_refresh;
                });
            if (standard_channel_entry == channels_.end())
                return;
            job_plan.emplace(
                prepare_job_locked(standard_channel_entry->second,
                                   current_job));
        }

        build_job_work(*job_plan);

        const std::scoped_lock lock(mutex_);
        const auto channel_entry = channels_.find(job_plan->channel_id);
        if (channel_entry == channels_.end() ||
            channel_entry->second.kind != ChannelKind::Standard ||
            !channel_entry->second.requires_frequent_job_refresh)
            return;
        Channel& channel = channel_entry->second;
        if (current_job->publication_sequence() != 0 &&
            current_job->publication_sequence() <
                channel.last_publication_sequence)
            return;
        channel.last_publication_sequence =
            std::max(channel.last_publication_sequence,
                     current_job->publication_sequence());
        commit_job_locked(
            channel, std::move(*job_plan),
            requires_new_prevhash_locked(channel, *current_job));
    } catch (const std::exception& error) {
        log::warning("Could not refresh SV2 job for {}: {}", connection_.peer(),
                     error.what());
    }
}

bool Session::remember_share_locked(const ShareKey& key) {
    if (seen_shares_.contains(key) || seen_shares_previous_.contains(key))
        return false;
    if (seen_shares_.size() >= stratum::kMaxSeenShares) {
        seen_shares_previous_ = std::move(seen_shares_);
        seen_shares_.clear();
    }
    seen_shares_.insert(key);
    return true;
}

void Session::send_share_rejection_locked(Channel* channel,
                                          const ShareSubmission& share,
                                          const std::string& address,
                                          std::string error_code) {
    ++shares_rejected_;
    if (channel)
        ++channel->shares_rejected;
    if (log::level() <= log::Level::Debug)
        log::debug("Rejected SV2 share from {} peer={} channel={} job={} ({})",
                   address, connection_.peer(), share.channel_id, share.job_id,
                   error_code);
    send_locked(encode_message(SubmitSharesError{
        share.channel_id, share.sequence_number, std::move(error_code)}));
}

void Session::reject_share_locked(Channel* channel, const ShareSubmission& share,
                                  std::string error_code,
                                  stratum::RejectClass reason) {
    pool_.note_rejected_share(
        channel ? channel->worker_accounting : stats::WorkerAccountingHandle{},
        channel ? channel->address : "", channel ? channel->worker : "", reason);
    send_share_rejection_locked(channel, share, channel ? channel->address : "",
                                std::move(error_code));
}

void Session::record_accepted_locked(Channel* channel,
                                     double credited_difficulty,
                                     double share_difficulty) {
    const int64_t current_wall_time =
        static_cast<int64_t>(std::time(nullptr));
    const double current_steady_time = stats::steady_seconds();
    protocol_errors_ = 0;
    if (channel) {
        ++channel->shares_since_retarget;
        ++channel->shares_accepted;
        channel->total_share_difficulty += credited_difficulty;
        channel->best_difficulty =
            std::max(channel->best_difficulty, share_difficulty);
        channel->last_share_timestamp = current_wall_time;
        channel->hashrate.add(credited_difficulty, current_steady_time);
    }
    ++shares_accepted_;
    total_share_difficulty_ += credited_difficulty;
    best_difficulty_ = std::max(best_difficulty_, share_difficulty);
    last_share_timestamp_ = current_wall_time;
    hashrate_.add(credited_difficulty, current_steady_time);
}

void Session::handle_submit_locked(const SubmitSharesStandard& message,
                                   std::unique_lock<std::mutex>& lock) {
    handle_share_locked({ChannelKind::Standard, message.channel_id,
                         message.sequence_number, message.job_id, message.nonce,
                         message.ntime, message.version, {}},
                        lock);
}

void Session::handle_submit_locked(const SubmitSharesExtended& message,
                                   std::unique_lock<std::mutex>& lock) {
    handle_share_locked({ChannelKind::Extended, message.channel_id,
                         message.sequence_number, message.job_id, message.nonce,
                         message.ntime, message.version, message.extranonce},
                        lock);
}

void Session::handle_share_locked(const ShareSubmission& share,
                                  std::unique_lock<std::mutex>& lock) {
    std::optional<PreparedShare> prepared = prepare_share_locked(share);
    if (!prepared)
        return;

    ShareValidation validation;
    lock.unlock();
    try {
        validation = validate_and_account_share(share, *prepared);
    } catch (...) {
        lock.lock();
        throw;
    }
    lock.lock();
    finish_share_locked(share, *prepared, std::move(validation));
}

std::optional<Session::PreparedShare> Session::prepare_share_locked(
    const ShareSubmission& share) {
    const auto channel_entry = channels_.find(share.channel_id);
    if (channel_entry == channels_.end()) {
        ++protocol_errors_;
        reject_share_locked(nullptr, share, "invalid-channel",
                            stratum::RejectClass::Malformed);
        return std::nullopt;
    }
    Channel& channel = channel_entry->second;
    if (channel.kind != share.kind) {
        ++protocol_errors_;
        reject_share_locked(&channel, share, "invalid-channel-type",
                            stratum::RejectClass::Malformed);
        return std::nullopt;
    }
    const auto job_entry = std::ranges::find_if(
        channel.jobs, [&](const auto& entry) { return entry.first == share.job_id; });
    if (job_entry == channel.jobs.end()) {
        reject_share_locked(&channel, share, "stale-share",
                            stratum::RejectClass::Stale);
        return std::nullopt;
    }
    const std::shared_ptr<IssuedJob> issued_job = job_entry->second;
    if (share.kind == ChannelKind::Extended &&
        share.extranonce.size() != issued_job->extranonce_size) {
        reject_share_locked(&channel, share, "invalid-extranonce-size",
                            stratum::RejectClass::Malformed);
        return std::nullopt;
    }
    Bytes submitted_extranonce(share.extranonce.begin(),
                               share.extranonce.end());
    if (!remember_share_locked(
            {share.channel_id, share.job_id, share.nonce, share.ntime,
             share.version, submitted_extranonce})) {
        reject_share_locked(&channel, share, "duplicate-share",
                            stratum::RejectClass::Duplicate);
        return std::nullopt;
    }

    if (share.ntime < issued_job->minimum_ntime ||
        share.ntime > maximum_ntime(issued_job->previous_hash_minimum_ntime,
                                    issued_job->previous_hash_received_at_steady,
                                    stats::steady_seconds())) {
        reject_share_locked(&channel, share, "invalid-ntime",
                            stratum::RejectClass::Ntime);
        return std::nullopt;
    }

    return PreparedShare{
        issued_job,
        std::move(submitted_extranonce),
        issued_job->target,
        version_mask_,
        channel.worker_accounting,
        channel.address,
        channel.worker,
    };
}

Session::ShareValidation Session::validate_and_account_share(
    const ShareSubmission& share, const PreparedShare& prepared) {
    const int64_t current_wall_time =
        static_cast<int64_t>(std::time(nullptr));
    std::expected<stratum::ShareResult, stratum::ShareRejection>
        validation_result;
    if (share.kind == ChannelKind::Standard) {
        const auto& work =
            std::get<stratum::StandardWork>(prepared.issued_job->work);
        validation_result =
            prepared.issued_job->source_job->validate_standard_share(
            {work.legacy_coinbase, work.merkle_root, share.ntime,
             share.nonce, share.version, prepared.version_rolling_mask,
             prepared.issued_target, current_wall_time});
    } else {
        const auto& work =
            std::get<stratum::ExtendedWork>(prepared.issued_job->work);
        validation_result =
            prepared.issued_job->source_job->validate_extended_share(
            work, {prepared.issued_job->extranonce_prefix,
                   prepared.submitted_extranonce,
                   prepared.issued_job->extranonce_size, share.ntime,
                   share.nonce,
                   share.version, prepared.version_rolling_mask,
                   prepared.issued_target, current_wall_time});
    }

    double credited_difficulty = 0.0;
    if (!validation_result) {
        pool_.note_rejected_share(
            prepared.worker_accounting, prepared.address, prepared.worker,
            stratum::reject_class_of(validation_result.error().reason));
    } else {
        credited_difficulty =
            util::difficulty_from_target(prepared.issued_target);
        pool_.note_accepted_share(
            prepared.worker_accounting, prepared.address, prepared.worker,
            credited_difficulty, validation_result->difficulty);
    }
    return {std::move(validation_result), credited_difficulty};
}

void Session::finish_share_locked(const ShareSubmission& share,
                                  const PreparedShare& prepared,
                                  ShareValidation&& validation) {
    const auto channel_entry = channels_.find(share.channel_id);
    Channel* channel =
        channel_entry == channels_.end() ? nullptr : &channel_entry->second;
    if (!validation.result) {
        const bool low_difficulty =
            validation.result.error().reason ==
            stratum::ShareReject::AboveTarget;
        send_share_rejection_locked(
            channel, share, prepared.address,
            low_difficulty ? "too-low-difficulty" : "invalid-share");
        return;
    }

    record_accepted_locked(channel, validation.credited_difficulty,
                           validation.result->difficulty);
    const double rounded_difficulty =
        std::max(1.0, std::round(validation.credited_difficulty));
    const uint64_t accepted_share_sum =
        rounded_difficulty >=
                static_cast<double>(std::numeric_limits<uint64_t>::max())
            ? std::numeric_limits<uint64_t>::max()
            : static_cast<uint64_t>(rounded_difficulty);
    send_locked(encode_message(SubmitSharesSuccess{
        share.channel_id, share.sequence_number, 1, accepted_share_sum}));
    if (log::level() <= log::Level::Debug)
        log::debug("Accepted SV2 share from {} peer={} channel={} diff {}/{}",
                    prepared.address, connection_.peer(), share.channel_id,
                    util::format_difficulty(validation.result->difficulty),
                    util::format_difficulty(
                        validation.credited_difficulty));
    if (validation.result->is_block)
        pending_blocks_.push_back(
            {prepared.issued_job->source_job,
             std::move(*validation.result),
             prepared.address, prepared.worker});
}

void Session::maybe_retarget() {
    const std::scoped_lock lock(mutex_);
    const auto config = pool_.runtime_config();
    if (channels_.empty())
        return;
    const double current_steady_time = stats::steady_seconds();
    for (auto& [channel_id, channel] : channels_) {
        if (channel.jobs.empty())
            continue;
        const auto& source_job = channel.jobs.back().second->source_job;
        const double elapsed =
            current_steady_time - channel.last_retarget_at_steady;
        util::uint256 requested_target = channel.target;
        double shares_per_minute = 0.0;
        if (config->variable_difficulty && elapsed >= config->vardiff_retarget_seconds) {
            shares_per_minute =
                elapsed > 0.0
                    ? static_cast<double>(channel.shares_since_retarget) / elapsed * 60.0
                    : 0.0;
            channel.shares_since_retarget = 0;
            channel.last_retarget_at_steady = current_steady_time;
            const double requested_difficulty =
                stratum::vardiff_next(channel.difficulty, shares_per_minute,
                                      config->vardiff_target_shares_per_minute,
                                      config->minimum_difficulty,
                                      config->maximum_difficulty);
            requested_target = util::target_from_difficulty(requested_difficulty);
        }
        const util::uint256 new_target = bounded_target(
            requested_target, channel.device_maximum_target, *config, *source_job);
        if (new_target == channel.target)
            continue;

        change_target_locked(channel, new_target);
        log::debug("SV2 vardiff {} channel {} -> {} ({:.1f} shares/min)",
                   connection_.peer(), channel_id,
                   util::format_difficulty(channel.difficulty), shares_per_minute);
    }
}

bool Session::requires_new_prevhash_locked(const Channel& channel,
                                           const stratum::Job& job) const {
    return channel.previous_hash.empty() ||
           channel.previous_hash != job.prevhash_internal() ||
           channel.previous_bits != job.bits();
}

void Session::change_target_locked(Channel& channel,
                                   const util::uint256& new_target) {
    // Future jobs follow SetTarget; active jobs retain their issued target.
    for (auto& [job_id, issued] : channel.jobs) {
        (void)job_id;
        if (issued->follows_channel_target)
            issued->target = new_target;
    }
    channel.target = new_target;
    channel.difficulty = util::difficulty_from_target(channel.target);
    send_locked(
        encode_message(SetTarget{channel.id, channel.target.le_bytes()}));
}

mining::ClientStats Session::stats(bool include_worker_accounting) const {
    const std::scoped_lock lock(mutex_);
    mining::ClientStats snapshot;
    // Use the lowest channel ID for deterministic connection-level identity.
    if (!channels_.empty()) {
        const Channel& representative_channel = channels_.begin()->second;
        snapshot.address = representative_channel.address;
        snapshot.worker = representative_channel.worker;
        snapshot.difficulty = representative_channel.difficulty;
    }
    snapshot.peer = connection_.peer();
    snapshot.user_agent = "SV2/" + user_agent_;
    snapshot.best_difficulty = best_difficulty_;
    snapshot.total_share_difficulty = total_share_difficulty_;
    snapshot.shares_accepted = shares_accepted_;
    snapshot.shares_rejected = shares_rejected_;
    snapshot.last_share_timestamp = last_share_timestamp_;
    snapshot.connected_at = connected_at_;
    const double current_steady_time = stats::steady_seconds();
    snapshot.connected_seconds =
        static_cast<int64_t>(current_steady_time - connected_at_steady_);
    snapshot.subscribed = !channels_.empty();
    snapshot.authorized = !channels_.empty();
    snapshot.channels.reserve(channels_.size());
    for (const auto& [channel_id, channel] : channels_) {
        (void)channel_id;
        mining::ClientChannelStats channel_stats;
        channel_stats.address = channel.address;
        channel_stats.worker = channel.worker;
        channel_stats.difficulty = channel.difficulty;
        channel_stats.best_difficulty = channel.best_difficulty;
        channel_stats.total_share_difficulty =
            channel.total_share_difficulty;
        channel_stats.shares_accepted = channel.shares_accepted;
        channel_stats.shares_rejected = channel.shares_rejected;
        channel_stats.last_share_timestamp = channel.last_share_timestamp;
        channel_stats.connected_seconds =
            static_cast<int64_t>(current_steady_time -
                                 channel.opened_at_steady);
        channel_stats.hashrate_windows =
            channel.hashrate.snapshot(current_steady_time);
        if (include_worker_accounting)
            channel_stats.worker_accounting = channel.worker_accounting;
        snapshot.channels.push_back(std::move(channel_stats));
    }
    snapshot.hashrate_windows = hashrate_.snapshot(current_steady_time);
    return snapshot;
}

bool Session::authorized() const {
    const std::scoped_lock lock(mutex_);
    return !channels_.empty();
}

bool Session::ever_authorized() const {
    const std::scoped_lock lock(mutex_);
    return ever_authorized_;
}

int Session::protocol_errors() const {
    const std::scoped_lock lock(mutex_);
    return protocol_errors_;
}

bool Session::should_close() const {
    const std::scoped_lock lock(mutex_);
    return close_after_response_;
}

} // namespace erikslund::sv2

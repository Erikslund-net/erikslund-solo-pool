#include "stratum/session.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cmath>
#include <ctime>
#include <format>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>

#include "core/logging.hpp"
#include "util/difficulty.hpp"
#include "util/hex.hpp"

namespace erikslund::stratum {

// File-local only (not in session.hpp): the dynamic JSON-RPC DOM type.
using json = glz::generic;

namespace {
constexpr std::chrono::seconds kControlLogInterval{1};
log::RateLimit control_warning_limit{kControlLogInterval};
log::RateLimit authorization_log_limit{log::kOperationalMessageInterval,
                                      log::kOperationalMessageBurst};
log::RateLimit difficulty_log_limit{log::kOperationalMessageInterval,
                                   log::kOperationalMessageBurst};

// Append `value` lowercased (no padding). For length-meaningful fields (job_id, and extranonce2
// which goes raw into the coinbase, so "ab" != "00ab") a short value must NOT collapse onto a
// valid full-width one.
void append_lower(std::string& out, std::string_view value) {
    for (char c : value)
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
}

// Append `value` lowercased and left-zero-padded to `width` hex chars. ONLY for fixed-width
// 4-byte fields (ntime/nonce/version), where a leading-zero spelling IS the same value.
void append_canonical_hex(std::string& out, std::string_view value, size_t width) {
    if (!value.empty() && value.size() < width)
        out.append(width - value.size(), '0');
    append_lower(out, value);
}

const std::string& or_empty(const std::optional<std::string>& value) {
    static const std::string kEmpty;
    return value ? *value : kEmpty;
}

std::string_view trim_spaces(std::string_view text) {
    const std::size_t first = text.find_first_not_of(" \t");
    if (first == std::string_view::npos)
        return {};
    const std::size_t last = text.find_last_not_of(" \t");
    return text.substr(first, last - first + 1);
}

std::optional<double> difficulty_from_password(std::string_view password) {
    while (!password.empty()) {
        const std::size_t separator = password.find(',');
        const std::string_view token = trim_spaces(password.substr(0, separator));

        std::string_view value;
        if (token.starts_with("d="))
            value = trim_spaces(token.substr(2));
        else if (token.starts_with("diff=") || token.starts_with("diff_"))
            value = trim_spaces(token.substr(5));

        if (!value.empty()) {
            const std::string text(value);
            double difficulty = 0.0;
            const char* const end = text.data() + text.size();
            if (const auto [position, error] =
                    std::from_chars(text.data(), end, difficulty);
                error == std::errc{} && position == end)
                return difficulty;
        }

        if (separator == std::string_view::npos)
            break;
        password.remove_prefix(separator + 1);
    }
    return std::nullopt;
}
} // namespace

double vardiff_next(double current, double shares_per_minute, double target, double min_difficulty,
                    double max_difficulty) {
    const double difficulty_cap =
        max_difficulty > 0.0 ? max_difficulty : std::numeric_limits<double>::max();
    current = std::clamp(current, min_difficulty, difficulty_cap);
    if (shares_per_minute > target * 2.0 && current < difficulty_cap)
        return current >= difficulty_cap / 2.0 ? difficulty_cap : current * 2.0;
    if (shares_per_minute < target / 2.0)
        return std::max(min_difficulty, current / 2.0);
    return current;
}

std::optional<double> clamp_suggested_difficulty(double suggested, double min_difficulty,
                                                 double max_difficulty) {
    if (!std::isfinite(suggested) || suggested <= 0.0)
        return std::nullopt;
    double clamped = std::max(suggested, min_difficulty);
    if (max_difficulty > 0.0)
        clamped = std::min(clamped, max_difficulty);
    return clamped;
}

Session::Session(PoolContext& pool, Connection& connection, Bytes extranonce1)
    : pool_(pool),
      connection_(connection),
      extranonce1_(std::move(extranonce1)),
      extranonce1_hex_(util::to_hex(extranonce1_)),
      difficulty_(0.0),
      connected_at_(static_cast<int64_t>(std::time(nullptr))), // wall: DISPLAYED
      connected_at_steady_(stats::steady_seconds()),           // monotonic
      last_retarget_(connected_at_steady_),                    // monotonic
      // Seed the window clock at connect time so the first share folds a real interval.
      hashrate_(std::span<const int, stats::kHashrateWindows.size()>(stats::kHashrateWindows),
                connected_at_steady_) {
    const auto config = pool.runtime_config();
    difficulty_ = std::max(config->initial_difficulty, config->minimum_difficulty);
}

void Session::maybe_retarget() {
    const std::scoped_lock lock(mutex_);
    const auto config = pool_.runtime_config();
    if (!config->variable_difficulty || !authorized_)
        return;
    const double now = stats::steady_seconds(); // monotonic
    const double elapsed = now - last_retarget_;
    if (elapsed < config->vardiff_retarget_seconds)
        return;

    const double shares_per_minute =
        elapsed > 0.0 ? (static_cast<double>(shares_since_retarget_) / elapsed) * 60.0 : 0.0;
    const double new_difficulty =
        vardiff_next(difficulty_, shares_per_minute, config->vardiff_target_shares_per_minute,
                     config->minimum_difficulty, config->maximum_difficulty);

    shares_since_retarget_ = 0;
    last_retarget_ = now;
    if (new_difficulty != difficulty_) {
        begin_difficulty_change(new_difficulty);
        do_send_set_difficulty();
        if (log::level() <= log::Level::Debug)
            log::debug("Vardiff {} -> {} ({:.1f} shares/min)", connection_.peer(),
                       util::format_difficulty(new_difficulty), shares_per_minute);
    }
}

mining::ClientStats Session::stats(bool include_worker_accounting) const {
    const std::scoped_lock lock(mutex_);
    mining::ClientStats snapshot;
    snapshot.address = address_.value_or("");
    snapshot.worker = worker_.value_or("");
    snapshot.peer = connection_.peer();
    snapshot.user_agent = user_agent_;
    snapshot.difficulty = difficulty_;
    snapshot.best_difficulty = best_difficulty_;
    snapshot.total_share_difficulty = total_share_difficulty_;
    snapshot.shares_accepted = shares_accepted_;
    snapshot.shares_rejected = shares_rejected_;
    snapshot.last_share_timestamp = last_share_timestamp_; // wall: DISPLAYED
    snapshot.connected_at = connected_at_;                 // wall: DISPLAYED
    const double now_steady = stats::steady_seconds();     // monotonic
    snapshot.connected_seconds = static_cast<int64_t>(now_steady - connected_at_steady_);
    snapshot.subscribed = subscribed_;
    snapshot.authorized = authorized_;
    snapshot.hashrate_windows = hashrate_.snapshot(now_steady);
    if (authorized_ && address_) {
        mining::ClientChannelStats channel;
        channel.address = *address_;
        channel.worker = worker_.value_or("");
        channel.difficulty = difficulty_;
        channel.best_difficulty = best_difficulty_;
        channel.total_share_difficulty = total_share_difficulty_;
        channel.shares_accepted = shares_accepted_;
        channel.shares_rejected = shares_rejected_;
        channel.last_share_timestamp = last_share_timestamp_;
        channel.connected_seconds = snapshot.connected_seconds;
        channel.hashrate_windows = snapshot.hashrate_windows;
        if (include_worker_accounting)
            channel.worker_accounting = worker_accounting_;
        snapshot.channels.push_back(std::move(channel));
    }
    return snapshot;
}

void Session::send(const json& message) {
    connection_.send_line(glz::write_json(message).value_or(""));
}

void Session::send_result(const json& id, json result) {
    send(make_result(id, std::move(result)));
}

void Session::send_result(const json& id, bool result) {
    make_result_line_into(response_scratch_, id, result); // reused buffer: no alloc at steady state
    connection_.send_line(response_scratch_);
}

void Session::send_error(const json& id, const StratumError& error) {
    // Count only client-misbehaviour errors toward the disconnect budget; normal-mining races
    // (stale/duplicate/low-difficulty) must never count.
    if (error.code == ERR_OTHER.code || error.code == ERR_UNAUTHORIZED.code ||
        error.code == ERR_NOT_SUBSCRIBED.code)
        ++protocol_errors_;
    make_error_line_into(response_scratch_, id, error);
    connection_.send_line(response_scratch_);
}

std::shared_ptr<const Session::Coinbase2Cache> Session::coinbase2_for(const Job& job) {
    if (!payout_script_)
        throw std::logic_error("coinbase2_for called before payout_script_ was set");
    if (!coinbase2_cache_ || coinbase2_cache_->job_id != job.job_id()) {
        Bytes coinbase2 = job.build_coinbase2(*payout_script_);
        std::string coinbase2_hex = util::to_hex(coinbase2);
        coinbase2_cache_ = std::make_shared<const Coinbase2Cache>(
            job.job_id(), std::move(coinbase2), std::move(coinbase2_hex));
    }
    return coinbase2_cache_;
}

void Session::rotate_seen_shares() {
    // Live set becomes the lookback set (coverage never drops to zero); two-generations-back
    // contents are discarded.
    seen_shares_previous_ = std::move(seen_shares_current_);
    seen_shares_current_.clear(); // moved-from: make it valid-and-empty explicitly
}

bool Session::remember(std::string key) {
    if (seen_shares_current_.contains(key) || seen_shares_previous_.contains(key))
        return false;
    if (seen_shares_current_.size() >= kMaxSeenShares)
        rotate_seen_shares();
    seen_shares_current_.insert(std::move(key));
    return true;
}

void Session::handle_line(std::string_view line) {
    // Parse outside the lock: parse_request touches no session state, so only dispatch needs the
    // mutex. Per-share hashing in handle_submit stays under the lock (reads difficulty/dedup set).
    const auto request = parse_request(line);
    if (!request)
        return;
    if (request->method == "mining.submit") [[likely]] {
        // Preserve shares already read before a control request marked the session for closing.
        handle_submit(request->id, request->params);
        return;
    }
    const std::scoped_lock lock(mutex_);
    if (!allow_control_request(std::chrono::steady_clock::now()))
        return;
    dispatch(*request);
}

bool Session::allow_control_request(std::chrono::steady_clock::time_point now) {
    if (should_close())
        return false;
    if (now > control_refill_at_) {
        const double elapsed = std::chrono::duration<double>(now - control_refill_at_).count();
        control_request_tokens_ = std::min(kControlRequestBurst,
            control_request_tokens_ + elapsed * kControlRequestsPerSecond);
        control_refill_at_ = now;
    }
    if (control_request_tokens_ < 1.0) {
        close_requested_.store(true, std::memory_order_relaxed);
        log::message_limited(log::Level::Warning, control_warning_limit,
                             "Closing {}: excessive Stratum control requests", connection_.peer());
        return false;
    }
    control_request_tokens_ -= 1.0;
    return true;
}

void Session::dispatch(const Request& request) {
    const std::string& method = request.method;
    if (method == "mining.subscribe")
        handle_subscribe(request.id, request.params);
    else if (method == "mining.authorize")
        handle_authorize(request.id, request.params);
    else if (method == "mining.configure")
        handle_configure(request);
    else if (method == "mining.suggest_difficulty")
        handle_suggest_difficulty(request);
    else if (method == "mining.extranonce.subscribe")
        send_result(request.id, false);
    else if (!request.id.is_null())
        connection_.send_line(make_error_line(request.id, ERR_OTHER));
}

void Session::send_set_difficulty() {
    const std::scoped_lock lock(mutex_);
    do_send_set_difficulty();
}

std::string Session::set_difficulty_line() {
    return make_set_difficulty_line(difficulty_);
}

void Session::do_send_set_difficulty() {
    connection_.send_line(set_difficulty_line());
}

void Session::send_notify(const Job& job, bool clean) {
    const std::scoped_lock lock(mutex_);
    const uint64_t publication_sequence = job.publication_sequence();
    if (publication_sequence != 0 &&
        publication_sequence <=
            last_notified_publication_sequence_)
        return;
    if (auto line = build_notify_line(job, clean))
        connection_.send_line(*line);
}

std::optional<std::string> Session::build_notify_line(const Job& job, bool clean) {
    if (!subscribed_ || !authorized_ || !payout_script_)
        return std::nullopt;
    last_notified_publication_sequence_ =
        std::max(last_notified_publication_sequence_,
                 job.publication_sequence());
    const std::shared_ptr<const Coinbase2Cache> coinbase2 = coinbase2_for(job);
    // Keep one generation of lookback on a clean job (old jobs still accept shares). Skip when the
    // live set is already empty, else we'd demote the empty set and discard a live generation.
    if (clean && !seen_shares_current_.empty())
        rotate_seen_shares();
    // Fast path: mining.notify fans out per client per broadcast; the json-tree dump dominated the
    // broadcast loop. Byte-identical (doctest-pinned).
    std::string line = make_notify_line(job.job_id(), job.prevhash_stratum(),
                                        job.coinbase1_hex(), coinbase2->coinbase2_hex,
                                        job.merkle_branch_hex(), job.version_hex(),
                                        job.nbits_hex(), job.ntime_hex(), clean);
    // The new difficulty (if any) is now in effect from this job on; stop honoring the old one.
    pending_difficulty_change_ = false;
    return line;
}

void Session::send_difficulty_then_work() {
    const std::string difficulty = set_difficulty_line();
    std::optional<std::string> notify;
    if (auto job = pool_.current_job())
        notify = build_notify_line(*job, /*clean=*/true);
    if (notify) {
        const std::array<std::string_view, 2> flight{difficulty, *notify};
        connection_.send_lines(flight);
    } else {
        connection_.send_line(difficulty);
    }
}

void Session::begin_difficulty_change(double new_difficulty) {
    if (!pending_difficulty_change_)
        previous_difficulty_ = difficulty_;
    difficulty_ = new_difficulty;
    pending_difficulty_change_ = true;
}

void Session::handle_subscribe(const json& id, const std::vector<std::string>& params) {
    if (!params.empty() && !params[0].empty())
        user_agent_ = log::sanitize(params[0]);
    subscribed_ = true;
    const std::string subscription_id = extranonce1_hex_;
    // result = [[["mining.set_difficulty", <sub>], ["mining.notify", <sub>]], <enonce1>, <en2size>]
    json set_difficulty_entry = json::array_t{};
    set_difficulty_entry.get_array().emplace_back(json(std::string("mining.set_difficulty")));
    set_difficulty_entry.get_array().emplace_back(json(subscription_id));
    json notify_entry = json::array_t{};
    notify_entry.get_array().emplace_back(json(std::string("mining.notify")));
    notify_entry.get_array().emplace_back(json(subscription_id));
    json subscriptions = json::array_t{};
    subscriptions.get_array().push_back(std::move(set_difficulty_entry));
    subscriptions.get_array().push_back(std::move(notify_entry));
    json result = json::array_t{};
    result.get_array().push_back(std::move(subscriptions));
    result.get_array().emplace_back(json(extranonce1_hex_));
    result.get_array().emplace_back(json(static_cast<double>(pool_.extranonce2_size())));
    send_result(id, std::move(result));
    // Client authorized BEFORE subscribing (unusual): it has no job yet, so send work now instead
    // of waiting for the next pool broadcast.
    if (authorized_ && payout_script_)
        send_difficulty_then_work();
}

void Session::handle_configure(const Request& request) {
    json result = json::object_t{};
    if (request.configure_version_rolling) {
        uint32_t client_mask = 0xffffffff;
        if (request.version_rolling_mask_present) {
            client_mask = 0;
            if (request.version_rolling_mask) {
                const std::string& mask = *request.version_rolling_mask;
                if (!mask.empty() && mask.size() <= 8 &&
                    mask.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)
                    client_mask = static_cast<uint32_t>(std::stoul(mask, nullptr, 16));
            }
        }
        version_mask_ = client_mask & pool_.version_mask();
        result["version-rolling"] = version_mask_ != 0;
        result["version-rolling.mask"] = std::format("{:08x}", version_mask_);
    }
    // BIP310: answer every requested extension. Only version-rolling is supported, so report false
    // for anything else (a strict miner may stall waiting otherwise).
    for (const std::string& extension : request.configure_extensions)
        if (extension != "version-rolling" && !result.contains(extension))
            result[extension] = false;
    send_result(request.id, std::move(result));
}

void Session::handle_authorize(const json& id, const std::vector<std::string>& params) {
    if (params.empty() || params[0].empty()) {
        send_error(id, ERR_OTHER);
        return;
    }
    // Stratum username is "<address>[.<worker>]"; only the payout address is validated.
    const std::string username = log::sanitize(params[0]);
    const auto dot = username.find('.');
    std::string address = username.substr(0, dot);

    // Validate into a local FIRST: a failed re-authorize must not overwrite the already-good
    // address_/payout_script_.
    auto script = pool_.validate_address(address);
    if (!script) {
        ++protocol_errors_;
        log::message_limited(log::Level::Warning, control_warning_limit,
                             "Rejecting worker {}: invalid payout address '{}'", connection_.peer(),
                             address); // already sanitized at ingress
        send_result(id, false);
        return;
    }
    if (authorized_ && payout_script_ && *payout_script_ != *script) {
        ++protocol_errors_;
        log::message_limited(log::Level::Warning, control_warning_limit,
                             "Refusing re-authorize on {}: payout address {} -> {} on one connection",
                             connection_.peer(), or_empty(address_), address); // sanitized at ingress
        send_result(id, false);
        return;
    }
    // Keep the first spelling so equivalent Bech32 forms share one accounting identity.
    if (authorized_ && address_)
        address = *address_;
    address_ = std::move(address);
    // Gate the worker to ASCII from the raw suffix: ascii_only drops non-ASCII so the
    // ASCII-only users/<address> file cannot be corrupted while preserving worker identity.
    const auto raw_dot = params[0].find('.');
    worker_ = raw_dot == std::string::npos ? std::string{}
                                           : log::ascii_only(params[0].substr(raw_dot + 1));
    payout_script_ = std::move(script);
    authorized_ = true;

    if (params.size() > 1) {
        const auto config = pool_.runtime_config();
        if (const auto requested = difficulty_from_password(params[1]); requested) {
            const auto clamped = clamp_suggested_difficulty(
                *requested, config->minimum_difficulty, config->maximum_difficulty);
            if (clamped && *clamped != difficulty_) {
                begin_difficulty_change(*clamped);
                shares_since_retarget_ = 0;
                last_retarget_ = stats::steady_seconds();
                log::message_limited(log::Level::Info, difficulty_log_limit,
                                     "Password difficulty {} -> {}", connection_.peer(),
                                     util::format_difficulty(*clamped));
            }
        }
    }

    // Register the worker so an idle authorized rig shows up (and persists) in the stats even
    // before its first share.
    worker_accounting_ = pool_.attach_worker(*address_, *worker_);
    send_result(id, true);
    log::message_limited(log::Level::Info, authorization_log_limit,
                         "Authorized {} (address={}, user_agent={}, extranonce1={})", connection_.peer(),
                         *address_, user_agent_, extranonce1_hex()); // both sanitized at ingress

    send_difficulty_then_work();
}

void Session::handle_suggest_difficulty(const Request& request) {
    // Advisory: a missing/malformed value is acked but ignored. dispatch() holds mutex_.
    if (request.suggested_difficulty) {
        const auto config = pool_.runtime_config();
        const auto clamped = clamp_suggested_difficulty(*request.suggested_difficulty,
                                                         config->minimum_difficulty,
                                                         config->maximum_difficulty);
        if (clamped && *clamped != difficulty_) {
            begin_difficulty_change(*clamped);
            shares_since_retarget_ = 0; // restart the vardiff window at the new baseline
            last_retarget_ = stats::steady_seconds();
            if (subscribed_)
                do_send_set_difficulty();
            log::message_limited(log::Level::Info, difficulty_log_limit,
                                 "Suggest-difficulty {} -> {}", connection_.peer(),
                                 util::format_difficulty(*clamped));
        }
    }
    send_result(request.id, true);
}

void Session::handle_submit(const json& id, const std::vector<std::string>& params) {
    std::shared_ptr<const Job> job;
    std::shared_ptr<const Coinbase2Cache> coinbase2;
    stats::WorkerAccountingHandle worker_accounting;
    std::string address, worker;
    std::optional<std::string> version_bits;
    double snap_difficulty = 0.0, snap_previous = 0.0;
    bool snap_pending = false;
    uint32_t snap_version_mask = 0;
    {
        const std::scoped_lock lock(mutex_);
        if (!authorized_) [[unlikely]] {
            send_error(id, ERR_UNAUTHORIZED);
            return;
        }
        if (!subscribed_) [[unlikely]] {
            send_error(id, ERR_NOT_SUBSCRIBED);
            return;
        }
        if (params.size() < 5) [[unlikely]] {
            send_error(id, ERR_OTHER);
            return;
        }

        const std::string& job_id = params[1];
        const std::string& extranonce2 = params[2];
        const std::string& ntime = params[3];
        const std::string& nonce = params[4];
        if (params.size() > 5 && !params[5].empty())
            version_bits = params[5];

        job = pool_.recent_job(job_id);
        if (!job) [[unlikely]] {
            ++shares_rejected_;
            pool_.note_rejected_share(worker_accounting_, or_empty(address_), or_empty(worker_),
                                      RejectClass::Stale);
            send_error(id, ERR_STALE);
            return;
        }

        if (extranonce2.size() > pool_.extranonce2_size() * 2 || ntime.size() > 8 ||
            nonce.size() > 8 || (version_bits && version_bits->size() > 8)) [[unlikely]] {
            ++shares_rejected_;
            pool_.note_rejected_share(worker_accounting_, or_empty(address_), or_empty(worker_),
                                      RejectClass::Malformed);
            send_error(id, ERR_OTHER);
            return;
        }

        if (!remember(make_dedup_key(*job, extranonce2, ntime, nonce, version_bits))) [[unlikely]] {
            ++shares_rejected_;
            pool_.note_rejected_share(worker_accounting_, or_empty(address_), or_empty(worker_),
                                      RejectClass::Duplicate);
            send_error(id, ERR_DUPLICATE);
            return;
        }

        coinbase2 = coinbase2_for(*job);
        worker_accounting = worker_accounting_;
        address = or_empty(address_);
        worker = or_empty(worker_);
        snap_difficulty = difficulty_;
        snap_previous = previous_difficulty_;
        snap_pending = pending_difficulty_change_;
        snap_version_mask = version_mask_;
    }

    ShareInput input;
    input.coinbase2 = coinbase2->coinbase2;
    input.extranonce1 = extranonce1_; // immutable after the ctor
    input.extranonce2_hex = params[2];
    input.ntime_hex = params[3];
    input.nonce_hex = params[4];
    const double accept_difficulty =
        snap_pending ? std::min(snap_difficulty, snap_previous) : snap_difficulty;
    input.share_target = util::target_from_difficulty(accept_difficulty);
    input.version_bits_hex = std::move(version_bits);
    input.version_mask = snap_version_mask;
    input.now_unix = static_cast<int64_t>(std::time(nullptr));

    const auto result = job->validate_share(input);

    if (!result) {
        pool_.note_rejected_share(worker_accounting, address, worker,
                                  reject_class_of(result.error().reason));
        if (log::level() <= log::Level::Debug) {
            if (result.error().reason == ShareReject::AboveTarget) {
                const auto current_job = pool_.current_job();
                log::debug(
                    "Rejected low-difficulty share from {} peer={} job={} current_job={} "
                    "hash_diff={} required={} session={} previous={} pending={}",
                    address, connection_.peer(), job->job_id(),
                    current_job ? current_job->job_id() : "none",
                    util::format_difficulty(result.error().difficulty),
                    util::format_difficulty(accept_difficulty),
                    util::format_difficulty(snap_difficulty),
                    util::format_difficulty(snap_previous), snap_pending);
            } else {
                log::debug("Rejected share from {} peer={} job={} ({})", address,
                           connection_.peer(), job->job_id(), reject_reason(result.error().reason));
            }
        }
        const std::scoped_lock lock(mutex_);
        ++shares_rejected_;
        send_error(id,
                   result.error().reason == ShareReject::AboveTarget ? ERR_LOW_DIFFICULTY : ERR_OTHER);
        return;
    }

    if (result->is_block)
        pool_.on_block_found(address, worker, *job, *result);

    double credited = snap_difficulty;
    if (snap_pending) {
        const double hi = std::max(snap_difficulty, snap_previous);
        const double lo = std::min(snap_difficulty, snap_previous);
        credited = result->difficulty >= hi ? hi : lo;
    }
    pool_.note_accepted_share(worker_accounting, address, worker, credited, result->difficulty);
    {
        const std::scoped_lock lock(mutex_);
        record_accepted_share_locked(credited, result->difficulty);
        send_result(id, true);
    }
    if (log::level() <= log::Level::Debug)
        log::debug("Accepted share from {} peer={} diff {}/{}", address, connection_.peer(),
                   util::format_difficulty(result->difficulty),
                   util::format_difficulty(credited));
}

void Session::record_accepted_share_locked(double credited, double share_difficulty) {
    const int64_t now_wall = static_cast<int64_t>(std::time(nullptr)); // wall: DISPLAYED
    const double now_steady = stats::steady_seconds();                 // monotonic

    ++shares_accepted_;
    protocol_errors_ = 0; // a valid share clears any accumulated protocol-error budget
    ++shares_since_retarget_;
    total_share_difficulty_ += credited;
    last_share_timestamp_ = now_wall;
    hashrate_.add(credited, now_steady);
    best_difficulty_ = std::max(best_difficulty_, share_difficulty);
}

std::string Session::make_dedup_key(const Job& job, std::string_view extranonce2,
                                    std::string_view ntime, std::string_view nonce,
                                    const std::optional<std::string>& version_bits) const {
    std::string key;
    key.reserve(job.job_id().size() + extranonce2.size() + 40);
    append_lower(key, job.job_id());
    key.push_back('|');
    append_lower(key, extranonce2);
    key.push_back('|');
    append_canonical_hex(key, ntime, 8);
    key.push_back('|');
    append_canonical_hex(key, nonce, 8);
    key.push_back('|');
    uint32_t version = job.version();
    if (version_bits) {
        const auto rolled = util::try_parse_hex_u32(*version_bits);
        if (!rolled || (*rolled & ~version_mask_) != 0) {
            // Invalid attempts must not reserve the key of a valid header.
            key += "invalid|";
            append_lower(key, *version_bits);
            std::format_to(std::back_inserter(key), "|{:08x}", version_mask_);
            return key;
        }
        version = (version & ~version_mask_) | *rolled;
    }
    std::format_to(std::back_inserter(key), "{:08x}", version);
    return key;
}

} // namespace erikslund::stratum

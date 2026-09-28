#include "pool/pool.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <ctime>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <limits>
#include <random>
#include <set>
#include <span>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>

#include <glaze/glaze.hpp>

#include "bitcoin/address.hpp"
#include "bitcoin/block_template.hpp"
#include "bitcoin/serialize.hpp"
#include "core/errors.hpp"
#include "core/logging.hpp"
#include "core/version.hpp"
#include "mining/work_identity.hpp"
#include "stats/poolstatus.hpp"
#include "sv2/session.hpp"
#include "util/checked_counter.hpp"
#include "util/endian.hpp"
#include "util/hex.hpp"
#include "util/sha256.hpp"

namespace erikslund {

namespace {
// Late-share window: how many superseded jobs still accept shares. Jobs rotate every ~30s, so the
// depth must cover a mean block interval or a still-valid same-tip share false-rejects as stale.
// 24 x 30s = 12 min. Each job retains its tx data (up to ~4MB mainnet), so ~96MB worst-case.
constexpr size_t kMaxRecentJobs = 24;
constexpr std::chrono::seconds kInconclusiveRetryDelay{5};
constexpr size_t kBlockHeaderHexCharacters = 160;
constexpr int64_t kRpcBlockNotFound = -5;

// How long a disconnected, never-mined registry row (authorize-only) lingers before prune evicts
// it -- applied REGARDLESS of user_stats_retention_days so authorize-churn can't pin the registry
// cap forever under a keep-forever (retention <= 0) setting.
constexpr int64_t kGhostRowGraceSeconds = 3600;

// Cheap shape gate on usernames before attempting the full address decode.
constexpr std::string_view kAddressChars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";

bool plausible_address(const std::string& address) {
    return !address.empty() && address.size() <= 100 &&
           address.find_first_not_of(kAddressChars) == std::string::npos;
}

enum class SubmitOutcome { Accepted, AlreadyKnown, Inconclusive, Rejected };
SubmitOutcome classify_submit(const std::optional<std::string>& rejection) {
    if (!rejection)
        return SubmitOutcome::Accepted;
    if (*rejection == "duplicate")
        return SubmitOutcome::AlreadyKnown;
    if (*rejection == "inconclusive" || *rejection == "duplicate-inconclusive")
        return SubmitOutcome::Inconclusive;
    return SubmitOutcome::Rejected;
}

struct SpooledBlockIdentity {
    int64_t height;
    std::string hash;
};

std::optional<SpooledBlockIdentity>
parse_spooled_block_identity(const std::filesystem::path& path, std::string_view block_hex) {
    if (path.extension() != ".hex")
        return std::nullopt;

    const std::string stem = path.stem().string();
    const size_t separator = stem.find('_');
    if (separator == std::string::npos || separator == 0 || separator != stem.rfind('_'))
        return std::nullopt;

    int64_t height = 0;
    const char* height_begin = stem.data();
    const char* height_end = height_begin + separator;
    const auto [parsed_end, error] = std::from_chars(height_begin, height_end, height);
    std::string hash = stem.substr(separator + 1);
    if (error != std::errc{} || parsed_end != height_end || height <= 0 || hash.size() != 64 ||
        !util::is_hex(hash))
        return std::nullopt;

    hash = util::to_hex(util::from_hex(hash));
    if (block_hex.size() < kBlockHeaderHexCharacters ||
        !util::is_hex(block_hex.substr(0, kBlockHeaderHexCharacters)))
        return std::nullopt;
    const Bytes header = util::from_hex(block_hex.substr(0, kBlockHeaderHexCharacters));
    if (util::to_hex_reversed(util::sha256d(header)) != hash)
        return std::nullopt;

    return SpooledBlockIdentity{height, std::move(hash)};
}

void ratchet_max(std::atomic<double>& value, double candidate) {
    for (double previous = value.load(std::memory_order_relaxed);
         candidate > previous &&
         !value.compare_exchange_weak(previous, candidate, std::memory_order_relaxed);)
        ;
}

template <typename Submission>
std::optional<Submission> wait_for_submission(std::deque<Submission>& queue, std::mutex& mutex,
                                              std::condition_variable_any& condition,
                                              const std::stop_token& stop) {
    std::unique_lock lock(mutex);
    while (!stop.stop_requested()) {
        condition.wait(lock, stop, [&queue] { return !queue.empty(); });
        if (stop.stop_requested())
            return std::nullopt;

        const auto now = std::chrono::steady_clock::now();
        const auto submission = std::find_if(queue.begin(), queue.end(), [now](const auto& queued) {
            return queued.retry_after <= now;
        });
        if (submission != queue.end()) {
            Submission result = std::move(*submission);
            queue.erase(submission);
            return result;
        }

        const auto next_retry =
            std::ranges::min_element(queue, {}, &Submission::retry_after)->retry_after;
        condition.wait_until(lock, stop, next_retry, [&queue] {
            const auto current = std::chrono::steady_clock::now();
            return std::ranges::any_of(queue, [current](const auto& queued) {
                return queued.retry_after <= current;
            });
        });
    }
    return std::nullopt;
}
} // namespace

Pool::Pool(Config config, bitcoin::WorkSource& source, uint64_t work_generation)
    : config_(std::move(config)),
      work_generation_(work_generation),
      source_(source),
      runtime_config_(std::make_shared<const RuntimeConfig>(config_.runtime_config())),
      started_(static_cast<int64_t>(std::time(nullptr))), // wall: DISPLAYED/STORED
      started_steady_(stats::steady_seconds()),           // monotonic
      // Seed the window clock at start so the first share folds a real interval.
      hashrate_windows_(std::span<const int, stats::kHashrateWindows.size()>(stats::kHashrateWindows),
                        started_steady_),
      sps_windows_(std::span<const int, stats::kSpsWindows.size()>(stats::kSpsWindows),
                   started_steady_) {
    if (work_generation_ == 0)
        throw std::invalid_argument("A reserved work generation is required");
    // Job IDs are wire handles; the coinbase identifier separates actual mining work.
    job_id_prefix_ = static_cast<uint32_t>(std::random_device{}()) ^ static_cast<uint32_t>(started_);
    extranonce1_counter_.store(static_cast<uint64_t>(started_));
    // Empty-block witness commitment: witness merkle root is the all-zero coinbase wtxid, so
    // commitment = sha256d(64 zero bytes).
    empty_commitment_ = "6a24aa21a9ed" + util::to_hex(util::sha256d(Bytes(64, 0)));
    submit_thread_ = std::jthread([this](const std::stop_token& stop) { submit_loop(stop); });
    recovery_thread_ = std::jthread([this](const std::stop_token& stop) { recovery_loop(stop); });
    if (!config_.sv2_ports.empty() || !config_.sv2_plaintext_ports.empty())
        publication_thread_ =
            std::jthread([this](const std::stop_token& stop) { publication_loop(stop); });
}

Pool::~Pool() {
    stop_workers();
}

void Pool::stop_workers() {
    submit_thread_.request_stop();
    recovery_thread_.request_stop();
    publication_thread_.request_stop();
    submit_cv_.notify_all();
    recovery_cv_.notify_all();
    publication_cv_.notify_all();
    if (submit_thread_.joinable())
        submit_thread_.join();
    if (recovery_thread_.joinable())
        recovery_thread_.join();
    if (publication_thread_.joinable())
        publication_thread_.join();
}

void Pool::shutdown() {
    stop_workers();
    // Workers have joined, so these queues are finite and final attempts cannot requeue.
    const auto final_attempt = [this](const PendingBlock& block) {
        if (submit_block(block))
            log::warning("Block {} remains unconfirmed at shutdown; any spooled copy will be "
                         "retried on startup", block.hash);
    };
    while (!submit_queue_.empty()) {
        auto block = std::move(submit_queue_.front());
        submit_queue_.pop_front();
        final_attempt(*block);
    }
    while (!recovery_queue_.empty()) {
        auto submission = std::move(recovery_queue_.front());
        recovery_queue_.pop_front();
        if (!submission.recovered_spool_path)
            final_attempt(*submission.block);
    }
    write_stats();
}

void Pool::detect_network() {
    const bitcoin::ChainInfo info = source_.detect_chain();
    const std::string& chain = info.chain;
    const auto detected = bitcoin::network_from_string(chain);
    if (!detected)
        log::warning("Unrecognized bitcoind chain '{}'; using regtest address rules -- "
                     "donation/payout addresses for other networks will be rejected", chain);
    network_ = detected.value_or(bitcoin::Network::Regtest);
    chain_name_ = chain; // raw chain string for display (keeps testnet3 vs testnet4 distinct)
    chain_blocks_.store(info.blocks);
    generator_ready_.store(true);
    log::info("Connected to bitcoind: chain={} blocks={}", chain, info.blocks);

    if (config_.donation_percent > 0.0 && !config_.donation_address.empty()) {
        if (auto script = bitcoin::address_to_script(config_.donation_address, network_)) {
            donation_script_ = *script;
            log::info("Donation enabled: {}% of each block to {}", config_.donation_percent,
                      config_.donation_address);
        } else {
            log::warning("Donation disabled: invalid donation_address '{}'",
                         config_.donation_address);
        }
    }
}

void Pool::set_connector_ready(bool ready) {
    connector_ready_.store(ready);
}

void Pool::reload_config(const RuntimeConfig& config) {
    auto replacement = std::make_shared<const RuntimeConfig>(config);
    runtime_config_.store(std::move(replacement));
    last_reload_rejected_.store(false, std::memory_order_relaxed);
    config_generation_.fetch_add(1, std::memory_order_relaxed);
    notify_new_block();
}

void Pool::note_config_reload_rejected() noexcept {
    last_reload_rejected_.store(true, std::memory_order_relaxed);
}

void Pool::set_sv2_authenticated_state(
    std::optional<bool> ready,
    std::optional<int64_t> certificate_expiry_timestamp) {
    sv2_certificate_expiry_timestamp_.store(
        certificate_expiry_timestamp.value_or(kUnknownCertificateExpiry),
        std::memory_order_relaxed);
    const AuthenticatedSv2State state =
        !ready
            ? AuthenticatedSv2State::Disabled
            : (*ready ? AuthenticatedSv2State::Ready
                      : AuthenticatedSv2State::Unavailable);
    sv2_authenticated_state_.store(
        state, std::memory_order_release);
}

std::string Pool::next_job_id() {
    return std::format("{:08x}{:08x}", job_id_prefix_, util::next_counter(job_counter_));
}

Bytes Pool::next_extranonce1() {
    const size_t counter_size = config_.extranonce1_size - config_.extranonce1_prefix.size();
    const uint64_t value = util::next_counter(extranonce1_counter_,
                                             util::counter_maximum(counter_size));
    Bytes extranonce1 = config_.extranonce1_prefix;
    extranonce1.resize(config_.extranonce1_size, 0);
    for (size_t index = 0; index < counter_size; ++index)
        extranonce1[extranonce1.size() - 1 - index] =
            static_cast<uint8_t>(value >> (8 * index));
    return extranonce1;
}

Pool::PublishOutcome Pool::broadcast_job(const std::shared_ptr<const stratum::Job>& job, bool clean,
                                         bool require_new_prevhash,
                                         const stratum::Job* replaceable) {
    {
        const std::unique_lock<std::shared_mutex> lock(jobs_mutex_);
        // Decide atomically so racing GBT and ZMQ updates cannot rebroadcast unchanged templates.
        if (current_job_ && current_job_->work_signature() == job->work_signature())
            return PublishOutcome::Duplicate;
        // Height monotonicity, atomic with publication: never let a lower-height job replace a
        // higher one. build_and_broadcast pre-checks this unlocked, so a concurrent fastblock can
        // publish a higher job in the gap; this re-check stops the lagging GBT yanking miners back.
        // Only the job whose parent the node abandoned may be replaced by lower work.
        if (current_job_ && job->height() < current_job_->height() &&
            current_job_.get() != replaceable)
            return PublishOutcome::StaleHeight;
        // Fastblock-only: if a concurrent GBT already published a full job for this tip, replacing
        // it with empty work would throw the fees away. Atomic with publication closes the race.
        if (require_new_prevhash && current_job_ &&
            current_job_->prevhash_stratum() == job->prevhash_stratum())
            return PublishOutcome::StalePrevhash;
        // Stamp publication order (atomic with the publish decision); sessions use it to drop a
        // notify already superseded by a newer publication.
        if (publish_counter_ == std::numeric_limits<uint64_t>::max())
            throw std::overflow_error("Work publication counter exhausted");
        job->set_publication_sequence(++publish_counter_);
        current_job_ = job;
        recent_jobs_[job->job_id()] = job;
        recent_order_.push_back(job->job_id());
        while (recent_order_.size() > kMaxRecentJobs) {
            recent_jobs_.erase(recent_order_.front());
            recent_order_.pop_front();
        }
    }
    std::vector<std::shared_ptr<ConnectedClient>> recipients;
    {
        const std::scoped_lock lock(mutex_);
        recipients = clients_;
    }
    if (!recipients.empty()) {
        const size_t count = recipients.size();
        const size_t begin = broadcast_cursor_.fetch_add(1, std::memory_order_relaxed) % count;
        for (size_t offset = 0; offset < count; ++offset)
            if (const auto& client = recipients[(begin + offset) % count];
                !client->publish_asynchronously)
                client->session->publish_job(*job, clean);
        // Publish SV1 work before optional SV2 work enters its queue.
        for (size_t offset = 0; offset < count; ++offset)
            if (const auto& client = recipients[(begin + offset) % count];
                client->publish_asynchronously)
                enqueue_publication(client, job, clean);
    }
    return PublishOutcome::Published;
}

void Pool::enqueue_publication(
    const std::shared_ptr<ConnectedClient>& recipient,
    const std::shared_ptr<const stratum::Job>& job, bool clean) {
    {
        const std::scoped_lock lock(mutex_, publication_mutex_);
        if (!std::ranges::contains(clients_, recipient))
            return;
        const auto pending = std::ranges::find_if(
            publication_queue_, [&](const PendingPublication& publication) {
                return publication.recipient->session ==
                       recipient->session;
            });
        if (pending == publication_queue_.end()) {
            publication_queue_.push_back({recipient, job, clean});
        } else {
            pending->clean = pending->clean || clean;
            if (job->publication_sequence() >=
                pending->job->publication_sequence())
                pending->job = job;
        }
    }
    publication_cv_.notify_one();
}

void Pool::publication_loop(const std::stop_token& stop) {
    std::unique_lock<std::mutex> lock(publication_mutex_);
    while (true) {
        publication_cv_.wait(lock, stop,
                             [this] { return !publication_queue_.empty(); });
        if (stop.stop_requested())
            return;

        PendingPublication publication = std::move(publication_queue_.front());
        publication_queue_.pop_front();
        lock.unlock();
        try {
            publication.recipient->session->publish_job(
                *publication.job, publication.clean);
        } catch (const std::exception& error) {
            log::warning("Deferred work publication failed for {}: {}",
                         publication.recipient->connection->peer(),
                         error.what());
        }
        lock.lock();
    }
}

std::shared_ptr<stratum::Job> Pool::make_job(bitcoin::BlockTemplate block_template, bool clean) {
    const uint64_t sequence = util::next_counter(job_counter_);
    Bytes work_identifier;
    work_identifier.reserve(mining::kWorkIdentifierSize);
    util::append_le64(work_identifier, work_generation_);
    util::append_le64(work_identifier, sequence);
    return std::make_shared<stratum::Job>(
        std::format("{:08x}{:08x}", job_id_prefix_, sequence), std::move(block_template),
        Bytes(config_.coinbase_signature.begin(), config_.coinbase_signature.end()),
        config_.extranonce1_size, config_.extranonce2_size, config_.coinbase_version, clean,
        donation_script_, config_.donation_percent, work_identifier);
}

bool Pool::parent_abandoned(const stratum::Job& job) {
    try {
        return source_.block_standing(util::to_hex_reversed(job.prevhash_internal())) ==
               bitcoin::BlockStanding::Abandoned;
    } catch (const std::exception& error) {
        static log::RateLimit standing_log;
        log::message_limited(log::Level::Warning, standing_log,
                             "Could not check whether bitcoind abandoned the current work's "
                             "parent: {}",
                             error.what());
        return false;
    }
}

void Pool::note_refused_template(const std::string& previousblockhash) {
    {
        const std::scoped_lock lock(mutex_);
        refused_tip_ = previousblockhash;
    }
    const double now = stats::steady_seconds();
    double accepted = 0.0;
    templates_refused_since_.compare_exchange_strong(accepted, now, std::memory_order_relaxed);
    // Pace the next refetch of an unchanged tip to the rebroadcast interval.
    last_broadcast_steady_.store(now);
}

bool Pool::templates_stalled(double now_steady) const {
    const double since = templates_refused_since_.load(std::memory_order_relaxed);
    return since > 0.0 &&
           now_steady - since > 2.0 * runtime_config_.load()->work_rebroadcast_seconds;
}

void Pool::build_and_broadcast(bitcoin::BlockTemplate block_template, bool clean) {
    static log::RateLimit refused_template_log;
    // Height monotonicity: a template BELOW the current job's height usually comes from a lagging
    // node, and broadcasting it would yank miners onto an orphan-doomed parent. It replaces the
    // current work only when the node abandoned that work's parent (invalidateblock, or a reorg
    // onto a lower-height chain); a node still catching up leaves the current work in place.
    std::shared_ptr<const stratum::Job> abandoned;
    if (const auto current = current_job();
        current && block_template.height < current->height()) {
        if (!parent_abandoned(*current)) {
            note_refused_template(block_template.previousblockhash);
            log::message_limited(log::Level::Warning, refused_template_log,
                                 "Ignoring a GBT at height {} below the current job's height {} "
                                 "(lagging bitcoind?); keeping the current work",
                                 block_template.height, current->height());
            return;
        }
        log::warning("bitcoind abandoned the parent of the height {} work (reorg or "
                     "invalidateblock); following its chain back to height {}",
                     current->height(), block_template.height);
        abandoned = current;
    }

    // Copy what the bookkeeping/logs below need BEFORE the move: make_job pilfers the template's
    // tx blob, leaving it partially moved-from.
    const int64_t height = block_template.height;
    const uint32_t version = block_template.version;
    const uint32_t txn_count = block_template.txn_count;
    const std::string prevhash = block_template.previousblockhash;

    const auto job = make_job(std::move(block_template), clean);

    const PublishOutcome outcome =
        broadcast_job(job, clean, /*require_new_prevhash=*/false, abandoned.get());
    if (outcome == PublishOutcome::StaleHeight) {
        note_refused_template(prevhash);
        log::message_limited(log::Level::Warning, refused_template_log,
                             "Ignoring a GBT at height {} below the current job's height (lagging "
                             "bitcoind?); keeping the current work",
                             height);
        return;
    }
    {
        const std::scoped_lock lock(mutex_);
        last_prevhash_ = prevhash;
        last_template_time_ = stats::steady_seconds(); // monotonic
        last_version_ = version;
        has_template_ = true;
        refused_tip_.clear();
    }
    templates_refused_since_.store(0.0, std::memory_order_relaxed);
    last_broadcast_steady_.store(stats::steady_seconds());

    if (outcome == PublishOutcome::Published)
        log::debug("New job {} height={} txns={} clean={}", job->job_id(), height, txn_count,
                   clean);
}

bool fastblock_eligible(bool has_template, const std::string& notified_tip,
                        const std::string& last_prevhash, int64_t next_height,
                        int64_t confirmations, const std::string& chain_name,
                        const std::string& bits_hex) {
    if (!has_template)
        return false;
    // No nBits, no empty job: the fastblock template reuses the new tip's bits verbatim.
    if (bits_hex.empty())
        return false;
    if (notified_tip == last_prevhash) // the GBT already advanced to this tip
        return false;
    // The notified hash must be the active tip now: a stale notification (>= 2) or reorged-away
    // one (-1) would put miners on a superseded parent.
    if (confirmations != 1)
        return false;
    if (next_height % 2016 == 0) // difficulty retarget -> the new tip's nBits don't apply
        return false;
    // Testnet's 20-minute rule makes required nBits depend on the new block's timestamp at every
    // height, so reusing the new tip's nBits can mint bad-diffbits work.
    if (chain_name == "test" || chain_name == "testnet4")
        return false;
    return true;
}

uint64_t block_subsidy(int64_t height, int64_t halving_interval) {
    const int64_t halvings = halving_interval > 0 ? height / halving_interval : 0;
    if (halvings >= 64)
        return 0;
    return 5000000000ULL >> halvings;
}

void Pool::on_zmq_block(const std::string& block_hash_display) {
    notify_new_block();
    if (runtime_config_.load()->fast_block_notify && !block_hash_display.empty()) {
        const auto current = current_job();
        // Cheap precheck (no RPC); the authoritative check repeats below. Gating testnet here
        // avoids a pointless header fetch per block where fastblock is permanently ineligible.
        bool maybe_eligible = false;
        {
            const std::scoped_lock lock(mutex_);
            maybe_eligible = has_template_ && current && !current->mines_on(block_hash_display) &&
                             block_hash_display != last_prevhash_ && chain_name_ != "test" &&
                             chain_name_ != "testnet4";
        }
        if (maybe_eligible) {
            try {
                // One header fetch grounds the empty job in consensus: the true next height (BIP34
                // coinbase height + exact subsidy across halvings), confirmations == 1 (active
                // tip), the new tip's nBits, and its median-time-past for the ntime floor.
                const bitcoin::HeaderFacts header =
                    source_.fetch_header(block_hash_display); // off the lock
                const int64_t next_height = header.height + 1;
                const int64_t confirmations = header.confirmations;
                const std::string& bits_hex = header.bits_hex;
                const uint32_t mediantime = header.mediantime;

                bool eligible = false;
                uint32_t version = 0;
                int64_t halving_interval = 210000;
                {
                    const std::scoped_lock lock(mutex_);
                    eligible = fastblock_eligible(has_template_, block_hash_display,
                                                  last_prevhash_, next_height,
                                                  confirmations, chain_name_, bits_hex);
                    if (eligible) {
                        version = last_version_;
                        halving_interval = chain_name_ == "regtest" ? 150 : 210000;
                    }
                }
                if (eligible) {
                    bitcoin::BlockTemplate block_template;
                    block_template.height = next_height;
                    block_template.version = version;
                    block_template.curtime =
                        std::max(static_cast<uint32_t>(std::time(nullptr)), mediantime + 1);
                    block_template.bits_hex = bits_hex;
                    block_template.bits = util::parse_hex_u32(bits_hex);
                    block_template.coinbase_value = block_subsidy(next_height, halving_interval);
                    block_template.previousblockhash = block_hash_display;
                    block_template.coinbase_script_sig_prefix =
                        bitcoin::serialize_height(next_height);
                    block_template.coinbase_witness = Bytes(32, 0);
                    block_template.coinbase_required_outputs.push_back(
                        {0, util::from_hex(empty_commitment_)});
                    const auto job = make_job(std::move(block_template), /*clean=*/true);
                    if (broadcast_job(job, /*clean=*/true, /*require_new_prevhash=*/true) ==
                        PublishOutcome::Published) {
                        last_broadcast_steady_.store(stats::steady_seconds());
                        log::debug("Fastblock: empty work for height {} on new block {}",
                                   next_height, block_hash_display);
                    }
                }
            } catch (const std::exception& e) {
                log::warning("Fastblock failed: {}", e.what());
            }
        }
    }
    // The early tip probe may have run before fastblock published its new parent.
    notify_new_block();
}

void Pool::refresh_work(const std::stop_token& stop) {
    bool refresh_failing = false;
    const auto report_failure = [&refresh_failing](const std::exception& error) {
        if (!std::exchange(refresh_failing, true))
            log::warning("Work refresh failed: {}", error.what());
    };

    while (!stop.stop_requested()) {
        try {
            const auto runtime_config = runtime_config_.load();
            // A mainnet template is multi-MB; fetching it every poll just to read
            // previousblockhash is ~25MB/s of allocator churn (OOMs a 512MB host). Gate the heavy
            // call on a ~100-byte tip probe: fetch only when the tip moved, a rebroadcast is due,
            // or we have no work at all.
            const bool refresh_due =
                stats::steady_seconds() - last_broadcast_steady_.load() >=
                runtime_config->work_rebroadcast_seconds;
            const auto job = current_job();
            bool fetch = refresh_failing || refresh_due || job == nullptr;
            if (!fetch) {
                const std::string tip = source_.get_tip();
                set_generator_ready(true);
                const std::scoped_lock lock(mutex_);
                // A tip whose template was refused as lower than the current work is refetched
                // only when a rebroadcast is due, not every poll.
                fetch = (!job->mines_on(tip) || tip != last_prevhash_) && tip != refused_tip_;
            }
            if (fetch) {
                auto block_template = source_.fetch_template();
                bool new_block = false;
                {
                    const std::scoped_lock lock(mutex_);
                    new_block = block_template.previousblockhash != last_prevhash_;
                }
                build_and_broadcast(std::move(block_template), new_block);
                set_generator_ready(true);
                if (std::exchange(refresh_failing, false))
                    log::info("Work refresh recovered");
            }
        } catch (const std::exception& e) {
            // A reachable node may still be unable to serve mining work.
            set_generator_ready(false);
            report_failure(e);
        }
        // Wait poll_interval, but wake immediately on a ZMQ block notification.
        const auto runtime_config = runtime_config_.load();
        std::unique_lock<std::mutex> wait_lock(wakeup_mutex_);
        wakeup_cv_.wait_for(wait_lock, stop,
                            std::chrono::duration<double>(runtime_config->poll_interval),
                            [this] { return new_block_flag_; });
        new_block_flag_ = false;
    }
}

std::shared_ptr<stratum::Session>
Pool::add_client(std::shared_ptr<stratum::Connection> connection) {
    const std::string peer = connection->peer();
    auto session =
        std::make_shared<stratum::Session>(*this, *connection, next_extranonce1());
    {
        const std::scoped_lock lock(mutex_);
        clients_.push_back(
            std::make_shared<ConnectedClient>(
                ConnectedClient{std::move(connection), session, false}));
    }
    static log::RateLimit connection_log_limit{log::kOperationalMessageInterval,
                                              log::kOperationalMessageBurst};
    log::message_limited(log::Level::Info, connection_log_limit,
                         "Client connected: {} (extranonce1={})", peer,
                         session->extranonce1_hex());
    return session;
}

std::shared_ptr<sv2::Session>
Pool::add_sv2_client(std::shared_ptr<sv2::Connection> connection) {
    const std::string peer = connection->peer();
    const auto maximum_payload_size = static_cast<uint32_t>(
        std::min(config_.max_line_bytes, static_cast<size_t>(sv2::kMaximumFramePayloadSize)));
    auto session = std::make_shared<sv2::Session>(
        *this, *connection, next_extranonce1(), maximum_payload_size);
    {
        const std::scoped_lock lock(mutex_);
        clients_.push_back(
            std::make_shared<ConnectedClient>(
                ConnectedClient{std::move(connection), session, true}));
    }
    static log::RateLimit connection_log_limit{log::kOperationalMessageInterval,
                                              log::kOperationalMessageBurst};
    log::message_limited(log::Level::Debug, connection_log_limit,
                         "SV2 client connected: {}", peer);
    return session;
}

void Pool::remove_client(const std::shared_ptr<mining::Client>& session) {
    const std::scoped_lock lock(mutex_, publication_mutex_);
    std::erase_if(clients_, [&](const auto& client) { return client->session == session; });
    std::erase_if(publication_queue_,
                  [&](const PendingPublication& publication) {
                      return publication.recipient->session == session;
                  });
}

size_t Pool::client_count() const {
    const std::scoped_lock lock(mutex_);
    return clients_.size();
}

std::optional<Bytes> Pool::validate_address(const std::string& address) {
    // Validate locally (bech32/base58 checksum + network prefix), deriving the scriptPubKey with
    // no RPC: an invalid-address flood stays cheap and miners can authorize during a bitcoind blip.
    if (!plausible_address(address))
        return std::nullopt;
    if (auto script = bitcoin::address_to_script(address, network_))
        return *script;
    return std::nullopt; // malformed or wrong-network address
}

std::shared_ptr<const stratum::Job> Pool::current_job() const {
    const std::shared_lock<std::shared_mutex> lock(jobs_mutex_);
    return current_job_;
}

std::shared_ptr<const stratum::Job> Pool::recent_job(const std::string& job_id) const {
    const std::shared_lock<std::shared_mutex> lock(jobs_mutex_);  // concurrent per-share reads
    const auto it = recent_jobs_.find(job_id);
    return it != recent_jobs_.end() ? it->second : nullptr;
}

std::string Pool::resolve_worker_key(const WorkerMap& workers, const std::string& worker) const {
    if (workers.contains(worker))
        return worker; // an existing row keeps its key
    const int cap = runtime_config_.load()->max_workers_per_address;
    if (!worker.empty() && cap > 0) {
        size_t named = 0;
        for (const auto& [name, _] : workers)
            named += !name.empty();
        if (named >= static_cast<size_t>(cap))
            return ""; // at the cap: this name folds into the bare-address bucket
    }
    return worker;
}

stats::WorkerAccountingHandle Pool::worker_entry(const std::string& address,
                                                 const std::string& worker) {
    // Caller holds user_stats_mutex_. The "" key is the bare-address bucket: always present-able.
    auto addr_it = user_stats_.find(address);
    if (addr_it == user_stats_.end()) {
        if (user_stats_.size() >= stats::kMaxUserFiles)
            return nullptr; // registry address cap (defense-in-depth vs an address-cycling attacker)
        addr_it = user_stats_.try_emplace(address).first;
    }
    auto& workers = addr_it->second;
    if (const auto worker_it = workers.find(worker); worker_it != workers.end())
        return worker_it->second;
    const std::string key = resolve_worker_key(workers, worker);
    if (const auto worker_it = workers.find(key); worker_it != workers.end())
        return worker_it->second;
    auto accounting = std::make_shared<stats::WorkerAccounting>(started_steady_);
    workers.emplace(key, accounting);
    return accounting;
}

stats::WorkerAccountingHandle Pool::attach_worker(const std::string& address,
                                                  const std::string& worker) {
    if (address.empty())
        return {};
    const int64_t now_wall = static_cast<int64_t>(std::time(nullptr));
    const std::scoped_lock lock(user_stats_mutex_);
    auto accounting = worker_entry(address, worker);
    if (accounting) // create a zero row if absent
        accounting->touch(now_wall);
    return accounting;
}

void Pool::note_accepted_share(const std::string& address, const std::string& worker,
                               double credited, double share_difficulty) {
    note_accepted_share({}, address, worker, credited, share_difficulty);
}

void Pool::note_accepted_share(const stats::WorkerAccountingHandle& accounting,
                               const std::string& address, const std::string& worker,
                               double credited, double share_difficulty) {
    accepted_shares_.fetch_add(1, std::memory_order_relaxed);
    total_share_difficulty_.fetch_add(credited, std::memory_order_relaxed);
    ratchet_max(best_difficulty_runtime_, share_difficulty);
    {
        const std::scoped_lock lock(stats_mutex_);
        const double now_steady = stats::steady_seconds();
        hashrate_windows_.add(credited, now_steady);
        sps_windows_.add(1.0, now_steady);
    }
    auto worker_accounting = accounting;
    if (!worker_accounting && !address.empty()) {
        const std::scoped_lock lock(user_stats_mutex_);
        worker_accounting = worker_entry(address, worker);
    }
    if (worker_accounting)
        worker_accounting->note_accepted(credited, share_difficulty);
}

void Pool::note_rejected_share(const std::string& address, const std::string& worker,
                               stratum::RejectClass reason) {
    note_rejected_share({}, address, worker, reason);
}

void Pool::note_rejected_share(const stats::WorkerAccountingHandle& accounting,
                               const std::string& address, const std::string& worker,
                               stratum::RejectClass reason) {
    rejected_by_class_[static_cast<std::size_t>(reason)].fetch_add(1,
                                                                  std::memory_order_relaxed);
    auto worker_accounting = accounting;
    if (!worker_accounting && !address.empty()) {
        const std::scoped_lock lock(user_stats_mutex_);
        worker_accounting = worker_entry(address, worker);
    }
    if (worker_accounting)
        worker_accounting->note_rejected();
}

void Pool::prune_user_stats(int64_t now) {
    // Evict worker rows that are idle AND disconnected. A mined row (last_share_ts > 0) ages out
    // only past the retention window (retention_days <= 0 keeps it forever); a never-mined row
    // (authorize-only) ages out after a short grace REGARDLESS of retention. Never evicts a
    // connected worker; a folded live worker resolves to its "" bucket key, protecting that row.
    const int retention_days = runtime_config_.load()->user_stats_retention_days;
    const bool retention_on = retention_days > 0;
    const int64_t ghost_cutoff = now - kGhostRowGraceSeconds;
    const int64_t retention_cutoff =
        retention_on ? now - static_cast<int64_t>(retention_days) * 86400 : 0;
    std::vector<std::string> expired_addresses;
    {
        const std::scoped_lock lock(user_stats_mutex_);
        for (auto addr_it = user_stats_.begin(); addr_it != user_stats_.end();) {
            auto& workers = addr_it->second;
            for (auto it = workers.begin(); it != workers.end();) {
                const auto& accounting = it->second;
                if (accounting.use_count() > 1) {
                    ++it;
                    continue;
                }
                bool expired = false;
                const auto [last_activity, last_share] = accounting->activity();
                if (last_activity > 0) {
                    if (last_share == 0)
                        expired = last_activity < ghost_cutoff; // never mined
                    else if (retention_on)
                        expired = last_activity < retention_cutoff; // mined, retention on
                    // else: mined + keep-forever -> never expired
                }
                if (expired)
                    it = workers.erase(it);
                else
                    ++it;
            }
            if (workers.empty()) {
                expired_addresses.push_back(addr_it->first);
                addr_it = user_stats_.erase(addr_it);
            } else {
                ++addr_it;
            }
        }
    }
    // Finish deletion before the next stats snapshot, without blocking authorizations on disk I/O.
    const auto users_directory = std::filesystem::path(config_.stats_directory) / "users";
    for (const auto& address : expired_addresses) {
        std::error_code ec;
        std::filesystem::remove(users_directory / address, ec);
    }
}

void Pool::notify_new_block() {
    {
        const std::scoped_lock lock(wakeup_mutex_);
        new_block_flag_ = true;
    }
    wakeup_cv_.notify_all();
}

void Pool::vardiff_loop(const std::stop_token& stop) {
    while (!stop.stop_requested()) {
        const int interval = std::max(5, runtime_config_.load()->vardiff_retarget_seconds / 2);
        for (int i = 0; i < interval && !stop.stop_requested(); ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (stop.stop_requested())
            break;
        std::vector<std::shared_ptr<ConnectedClient>> clients;
        {
            const std::scoped_lock lock(mutex_);
            clients = clients_;
        }
        for (const auto& client : clients) {
            // One client's retarget throwing must not kill the vardiff thread.
            try {
                client->session->maybe_retarget();
            } catch (const std::exception& e) {
                log::warning("vardiff retarget failed for a client: {}", e.what());
            }
        }
    }
}

void Pool::status_loop(const std::stop_token& stop) {
    while (!stop.stop_requested()) {
        const double interval = std::max(1.0, runtime_config_.load()->status_interval_seconds);
        for (double slept = 0.0; slept < interval && !stop.stop_requested(); slept += 0.5)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (stop.stop_requested())
            break;
        write_stats();
        std::string tip;
        {
            const std::scoped_lock lock(mutex_);
            tip = last_prevhash_;
        }
        if (!stop.stop_requested())
            source_.maybe_failback(tip);
    }
}

void Pool::recover_stats() {
    if (const auto prior = stats::read_pool_status(config_.stats_directory)) {
        baseline_difficulty_ = prior->accepted_diff;
        baseline_best_difficulty_ = prior->best_share;
        blocks_found_.store(prior->blocks_found);
        last_block_found_.store(prior->last_block_found);
        {
            const std::scoped_lock lock(mutex_);
            blocks_by_address_ = prior->blocks_by_address;
        }
        log::info("Recovered stats from {}/pool/pool.status: accepted_diff={:.0f} best={:.0f} "
                  "blocks_found={}",
                  config_.stats_directory, baseline_difficulty_, baseline_best_difficulty_,
                  prior->blocks_found);
    }
}

void Pool::recover_user_stats() {
    const auto recovered = stats::read_user_stats(config_.stats_directory);
    if (recovered.empty())
        return;
    // The prune clock is the last SHARE time (`lastshare`), NOT the file mtime -- files are
    // rewritten every cycle, so mtime would reset every idle row's retention clock on restart and
    // make evicted data immortal. Skip never-mined rows and rows already past retention.
    const auto runtime_config = runtime_config_.load();
    const int retention_days = runtime_config->user_stats_retention_days;
    const int64_t now_wall = static_cast<int64_t>(std::time(nullptr));
    const int64_t cutoff = retention_days > 0 ? now_wall - static_cast<int64_t>(retention_days) * 86400
                                              : std::numeric_limits<int64_t>::min();

    // Two passes so the file-age decay is applied ONCE per resolved key, even when several file
    // rows fold onto the same bucket (lowered max_workers_per_address).
    struct Accum {
        std::array<double, stats::kHashrateWindows.size()> windows{};
        uint64_t shares_accepted = 0;
        uint64_t shares_rejected = 0;
        double best_difficulty = 0.0;
        int64_t last_share_ts = 0;
        double max_age = 0.0;
    };
    std::map<std::string, std::map<std::string, Accum>> by_address;
    for (const auto& rw : recovered) {
        if (rw.address.empty() || rw.last_share_ts == 0 || rw.last_share_ts < cutoff)
            continue;
        auto& keys = by_address[rw.address];
        std::string key = rw.worker; // re-apply the admission cap against the keys seen so far
        if (!key.empty() && !keys.contains(key) && runtime_config->max_workers_per_address > 0) {
            const auto named =
                std::ranges::count_if(keys, [](const auto& entry) { return !entry.first.empty(); });
            if (named >= static_cast<int64_t>(runtime_config->max_workers_per_address))
                key.clear();
        }
        Accum& a = keys[key];
        for (std::size_t i = 0; i < a.windows.size(); ++i)
            a.windows[i] += rw.hashrate_windows[i];
        a.shares_accepted += rw.shares_accepted;
        a.shares_rejected += rw.shares_rejected;
        a.best_difficulty = std::max(a.best_difficulty, rw.best_difficulty);
        a.last_share_ts = std::max(a.last_share_ts, rw.last_share_ts);
        a.max_age = std::max(a.max_age, rw.file_age_seconds);
    }

    size_t rows = 0;
    const std::scoped_lock lock(user_stats_mutex_);
    for (const auto& [address, keys] : by_address)
        for (const auto& [key, a] : keys) {
            auto accounting = worker_entry(address, key);
            if (!accounting)
                continue; // registry address cap hit during recovery
            accounting->recover(a.shares_accepted, a.shares_rejected, a.best_difficulty,
                                a.last_share_ts, a.windows, started_steady_,
                                a.max_age); // decay by file age, once
            ++rows;
        }
    log::info("Recovered {} worker stat row(s) from {}/users (hashrates decayed by file age)", rows,
              config_.stats_directory);
}

void Pool::write_stats() {
    try {
        // Prune FIRST so an eviction-cycle write doesn't re-publish the just-evicted rows to disk
        // (whose mtime would reset the prune clock on a later restart).
        prune_user_stats(static_cast<int64_t>(std::time(nullptr)));

        const auto snap = snapshot(/*include_workers=*/true); // the file writer needs the registry
        const int retention_days = runtime_config_.load()->user_stats_retention_days;
        stats::write_pool_status(config_.stats_directory, snap);
        stats::write_user_files(config_.stats_directory, snap, stats::kMaxUserFiles,
                                retention_days * 86400.0);
    } catch (const std::exception& e) {
        log::warning("Failed to write stats to {}: {}", config_.stats_directory, e.what());
    }
}

void Pool::spool_block(const PendingBlock& block) {
    try {
        const auto sync_descriptor = [](int descriptor) {
            int result;
            do {
                result = ::fsync(descriptor);
            } while (result < 0 && errno == EINTR);
            return result < 0 ? errno : 0;
        };
        const auto sync_directory = [&sync_descriptor](const std::filesystem::path& path) {
            int descriptor;
            do {
                descriptor = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            } while (descriptor < 0 && errno == EINTR);
            if (descriptor < 0) {
                const int error = errno;
                throw std::system_error(error, std::generic_category(), "open " + path.string());
            }

            const int error = sync_descriptor(descriptor);
            ::close(descriptor);
            if (error != 0)
                throw std::system_error(error, std::generic_category(), "fsync " + path.string());
        };

        const std::filesystem::path dir =
            std::filesystem::absolute(std::filesystem::path(config_.stats_directory) / "blocks");
        auto existing_directory = dir;
        while (!std::filesystem::exists(existing_directory))
            existing_directory = existing_directory.parent_path();
        std::filesystem::create_directories(dir);
        const std::filesystem::path path = dir / std::format("{}_{}.hex", block.height, block.hash);
        // Rename only complete files so recovery never reads a partial block.
        const std::filesystem::path temp_path =
            path.string() + ".tmp." + std::to_string(static_cast<long>(::getpid()));
        {
            errno = 0;
            std::ofstream out(temp_path, std::ios::binary);
            if (!out)
                throw std::runtime_error("open " + temp_path.string() + ": " +
                                         std::generic_category().message(errno ? errno : EIO));
            out << block.hex << "\n";
            out.flush();
            if (!out)
                throw std::runtime_error("write " + temp_path.string() + ": " +
                                         std::generic_category().message(errno ? errno : EIO));
            const int error = sync_descriptor(out.native_handle());
            if (error != 0)
                throw std::system_error(error, std::generic_category(),
                                        "fsync " + temp_path.string());
            out.close();
            if (!out)
                throw std::runtime_error("close " + temp_path.string() + ": " +
                                         std::generic_category().message(errno ? errno : EIO));
        }
        std::filesystem::rename(temp_path, path);
        // Persist the renamed file and every newly created directory entry.
        for (auto directory = dir;; directory = directory.parent_path()) {
            sync_directory(directory);
            if (directory == existing_directory)
                break;
        }
        log::info("Spooled block to {} (address={} worker={}; recover with: bitcoin-cli "
                    "submitblock <contents>)",
                    path.string(), block.address, block.worker);
    } catch (const std::exception& e) {
        log::error("Could not spool block height={} hash={}: {}; HEX FOLLOWS: {}", block.height,
                   block.hash, e.what(), block.hex);
    }
}

void Pool::resubmit_spooled_blocks() {
    const std::filesystem::path dir = std::filesystem::path(config_.stats_directory) / "blocks";
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) {
        if (ec)
            log::warning("Could not inspect block spool {}: {}", dir.string(), ec.message());
        return;
    }
    std::vector<std::filesystem::path> spooled;
    std::filesystem::directory_iterator entry(dir, ec);
    for (; !ec && entry != std::filesystem::directory_iterator(); entry.increment(ec))
        if (entry->path().extension() == ".hex")
            spooled.push_back(entry->path());
    if (ec)
        log::warning("Could not fully scan block spool {}: {}", dir.string(), ec.message());
    for (const auto& path : spooled) {
        std::string block_hex;
        {
            std::ifstream in(path, std::ios::binary);
            if (!in) {
                log::warning("Could not read spooled block {}; leaving it on disk",
                             path.filename().string());
                continue;
            }
            block_hex.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
            if (in.bad()) {
                log::warning("Could not fully read spooled block {}; leaving it on disk",
                             path.filename().string());
                continue;
            }
        }
        while (!block_hex.empty() && std::isspace(static_cast<unsigned char>(block_hex.back())))
            block_hex.pop_back();
        if (block_hex.empty()) {
            log::warning("Ignoring empty spooled block {}; leaving it on disk",
                         path.filename().string());
            continue;
        }

        const auto identity = parse_spooled_block_identity(path, block_hex);
        if (!identity)
            log::warning("Could not read height and hash from spooled block name {}; stale retry "
                         "detection is disabled",
                         path.filename().string());
        auto block = std::make_shared<PendingBlock>(PendingBlock{
            identity ? identity->height : -1,
            identity ? identity->hash : std::string{},
            std::move(block_hex),
            "",
            "",
        });
        {
            const std::scoped_lock lock(recovery_mutex_);
            const auto [tracked, inserted] = tracked_recovered_blocks_.insert(path);
            if (!inserted)
                continue;
            try {
                recovery_queue_.push_back(
                    DeferredSubmission{.block = std::move(block), .recovered_spool_path = path});
            } catch (...) {
                tracked_recovered_blocks_.erase(tracked);
                throw;
            }
        }
        log::warning("Queued block {} spooled by a previous run", path.filename().string());
        recovery_cv_.notify_one();
    }
}

api::PoolSnapshot Pool::snapshot(bool include_workers) const {
    // starttime is the wall epoch (started_); everything else here is a duration.
    const double now_steady = stats::steady_seconds();
    api::PoolSnapshot snapshot;
    snapshot.version = kVersion;
    snapshot.chain = chain_name_;
    snapshot.rpc_url = config_.rpc_url;
    snapshot.bitcoind_nodes = source_.endpoint_urls();
    snapshot.bitcoind_active_index = source_.active_index();
    snapshot.pid = ::getpid();
    snapshot.starttime = started_;
    snapshot.uptime = static_cast<int64_t>(now_steady - started_steady_);
    snapshot.config_generation = config_generation_.load(std::memory_order_relaxed);
    snapshot.last_reload_rejected = last_reload_rejected_.load(std::memory_order_relaxed);
    snapshot.generator_ready = generator_ready_.load();
    snapshot.connector_ready = connector_ready_.load();
    const AuthenticatedSv2State authenticated_sv2_state =
        sv2_authenticated_state_.load(std::memory_order_acquire);
    if (authenticated_sv2_state != AuthenticatedSv2State::Disabled)
        snapshot.sv2_authenticated_ready =
            authenticated_sv2_state == AuthenticatedSv2State::Ready;
    const int64_t certificate_expiry_timestamp =
        sv2_certificate_expiry_timestamp_.load(std::memory_order_relaxed);
    if (certificate_expiry_timestamp != kUnknownCertificateExpiry)
        snapshot.sv2_certificate_expiry_timestamp =
            certificate_expiry_timestamp;
    const std::time_t snapshot_time = std::time(nullptr);
    if (snapshot.sv2_authenticated_ready.value_or(false) &&
        certificate_expiry_timestamp != kUnknownCertificateExpiry &&
        snapshot_time >= 0 &&
        static_cast<uint64_t>(snapshot_time) >
            static_cast<uint64_t>(certificate_expiry_timestamp))
        snapshot.sv2_authenticated_ready = false;
    snapshot.bitcoind_reachable = snapshot.generator_ready;
    snapshot.blocks_found = blocks_found_.load();
    snapshot.last_block_found = last_block_found_.load();
    snapshot.shares_accepted = accepted_shares_.load(std::memory_order_relaxed);
    snapshot.jobs_created = job_counter_.load();

    std::shared_ptr<const stratum::Job> job;
    std::vector<std::shared_ptr<ConnectedClient>> clients;
    double last_template = 0.0;
    {
        const std::shared_lock<std::shared_mutex> jobs_lock(jobs_mutex_);
        job = current_job_;
        snapshot.recent_jobs_cached = recent_jobs_.size();
    }
    {
        const std::scoped_lock lock(mutex_);
        clients = clients_;
        last_template = last_template_time_;
        snapshot.blocks_by_address = blocks_by_address_;
    }
    {
        const std::scoped_lock lock(stats_mutex_);
        snapshot.hashrate_windows = hashrate_windows_.snapshot(now_steady);
        snapshot.sps_windows = sps_windows_.snapshot(now_steady);
    }
    const double total_difficulty =
        total_share_difficulty_.load(std::memory_order_relaxed);

    snapshot.stratifier_ready = job != nullptr;
    snapshot.ready = snapshot.generator_ready && snapshot.connector_ready && job != nullptr &&
                     !templates_stalled(now_steady);
    if (job) {
        snapshot.height = job->height();
        snapshot.current_job = job->job_id();
        snapshot.network_diff = job->network_difficulty();
        snapshot.txns_in_job = job->txn_count();
        snapshot.merkle_branch_len = job->merkle_branch_hex().size();
        snapshot.tip_height = job->height() - 1;
    } else if (chain_blocks_.load() >= 0) {
        snapshot.tip_height = chain_blocks_.load();
    }
    if (last_template > 0.0)
        snapshot.last_template_age_sec = static_cast<int64_t>(now_steady - last_template);

    double best_difficulty = 0.0;
    std::set<std::string> addresses;
    std::set<stats::WorkerAccountingHandle,
             std::owner_less<stats::WorkerAccountingHandle>>
        connected_accounting;
    size_t active_workers = 0;
    snapshot.clients.reserve(clients.size());
    for (const auto& client : clients) {
        const auto session_stats = client->session->stats(include_workers);
        const auto append_client_snapshot =
            [&](const mining::ClientChannelStats* channel) {
                api::ClientSnapshot client_snapshot;
                client_snapshot.address =
                    channel ? channel->address : session_stats.address;
                client_snapshot.worker =
                    channel ? channel->worker : session_stats.worker;
                client_snapshot.peer = session_stats.peer;
                client_snapshot.user_agent = session_stats.user_agent;
                client_snapshot.difficulty =
                    channel ? channel->difficulty : session_stats.difficulty;
                client_snapshot.best_difficulty =
                    channel ? channel->best_difficulty
                            : session_stats.best_difficulty;
                client_snapshot.total_share_diff =
                    channel ? channel->total_share_difficulty
                            : session_stats.total_share_difficulty;
                client_snapshot.shares_accepted =
                    channel ? channel->shares_accepted
                            : session_stats.shares_accepted;
                client_snapshot.shares_rejected =
                    channel ? channel->shares_rejected
                            : session_stats.shares_rejected;
                client_snapshot.last_share_ts =
                    channel ? channel->last_share_timestamp
                            : session_stats.last_share_timestamp;
                client_snapshot.connected_for =
                    channel ? channel->connected_seconds
                            : session_stats.connected_seconds;
                client_snapshot.subscribed = session_stats.subscribed;
                client_snapshot.authorized = session_stats.authorized;
                client_snapshot.hashrate_windows =
                    channel ? channel->hashrate_windows
                            : session_stats.hashrate_windows;
                snapshot.clients.push_back(std::move(client_snapshot));
            };

        if (session_stats.channels.empty()) {
            append_client_snapshot(nullptr);
        } else {
            active_workers += session_stats.channels.size();
            for (const auto& channel : session_stats.channels) {
                addresses.insert(channel.address);
                if (include_workers && channel.worker_accounting)
                    connected_accounting.insert(channel.worker_accounting);
                append_client_snapshot(&channel);
            }
        }
        best_difficulty = std::max(best_difficulty, session_stats.best_difficulty);
    }
    // Sample the persistent registry into snapshot.workers ONLY for the stats-file writer; the HTTP
    // path skips this O(registry) walk and its per-worker rate locks.
    if (include_workers) {
        struct WorkerEntry {
            std::string address;
            std::string worker;
            stats::WorkerAccountingHandle accounting;
        };
        std::vector<WorkerEntry> worker_entries;
        {
            const std::scoped_lock lock(user_stats_mutex_);
            for (const auto& [address, workers] : user_stats_)
                for (const auto& [worker, accounting] : workers)
                    worker_entries.push_back({address, worker, accounting});
        }
        snapshot.workers.reserve(worker_entries.size());
        for (auto& entry : worker_entries) {
            const auto worker_stats = entry.accounting->snapshot(now_steady);
            api::WorkerSnapshot worker_snapshot;
            worker_snapshot.address = std::move(entry.address);
            worker_snapshot.worker = std::move(entry.worker);
            worker_snapshot.connected = connected_accounting.contains(entry.accounting);
            worker_snapshot.shares_accepted = worker_stats.shares_accepted;
            worker_snapshot.shares_rejected = worker_stats.shares_rejected;
            worker_snapshot.best_difficulty = worker_stats.best_difficulty;
            worker_snapshot.last_share_ts = worker_stats.last_share_ts;
            worker_snapshot.hashrate_windows = worker_stats.hashrate_windows;
            snapshot.workers.push_back(std::move(worker_snapshot));
        }
    }

    snapshot.connected = active_workers;
    snapshot.users = addresses.size();
    for (size_t cls = 0; cls < rejected_by_class_.size(); ++cls) {
        snapshot.shares_rejected_by_class[cls] =
            rejected_by_class_[cls].load(std::memory_order_relaxed);
        snapshot.shares_rejected += snapshot.shares_rejected_by_class[cls];
    }
    // Pool-wide best: the runtime scalar (survives a registry prune) folded with live clients and
    // the restart baseline.
    snapshot.best_share =
        std::max({best_difficulty, baseline_best_difficulty_,
                  best_difficulty_runtime_.load(std::memory_order_relaxed)});
    snapshot.accepted_diff = baseline_difficulty_ + total_difficulty;
    snapshot.hashrate_estimate =
        snapshot.uptime > 0 ? total_difficulty * stats::kHashesPerDiff1Share /
                                  static_cast<double>(snapshot.uptime)
                            : 0.0;
    return snapshot;
}

bool Pool::ready() const {
    return generator_ready_.load() && connector_ready_.load() && current_job() != nullptr &&
           !templates_stalled(stats::steady_seconds());
}

void Pool::on_block_found(const std::string& address, const std::string& worker,
                          const stratum::Job& job, const stratum::ShareResult& result) {
    // PendingBlock outlives the ShareResult via submit_queue_, so materialize the hash view.
    // submitblock runs on the submit thread; blocking this reactor thread would stall its clients.
    std::shared_ptr<const PendingBlock> block = std::make_shared<PendingBlock>(PendingBlock{
        job.height(), std::string(result.block_hash_hex()),
        job.build_block_hex(result.legacy_coinbase, result.header), address, worker});
    {
        const std::scoped_lock lock(submit_mutex_);
        submit_queue_.push_back(block);
    }
    submit_cv_.notify_one(); // Queue submission before potentially blocking log and disk work.
    spool_block(*block);
    log::info("BLOCK CANDIDATE height={} hash={} diff={:.3f} address={} worker={}", job.height(),
              result.block_hash_hex(), result.difficulty, address, worker);
}

bool Pool::credit_block(const PendingBlock& block) {
    {
        const std::scoped_lock lock(mutex_);
        if (!credited_blocks_.insert(block.hash).second)
            return false;
        if (!block.address.empty())
            ++blocks_by_address_[block.address];
    }
    ++blocks_found_;
    last_block_found_.store(static_cast<int64_t>(std::time(nullptr)));
    return true;
}

bool Pool::submit_block(const PendingBlock& block) {
    try {
        const auto rejection = source_.submit_block_hex(block.hex);
        switch (classify_submit(rejection)) {
        case SubmitOutcome::Accepted:
            credit_block(block);
            log::info("BLOCK ACCEPTED height={} hash={} address={} worker={}", block.height,
                        block.hash, block.address, block.worker);
            return false;
        case SubmitOutcome::AlreadyKnown:
            // Already in a chain -- a win, not a rejection. This can be the FIRST reply we ever see
            // for a block we won: if the node accepted an earlier submit but its response was lost
            // (flaky link), the pool retries and bitcoind answers "duplicate", so no ACCEPTED reply
            // ever arrives. Credit it unless something already did -- credit_block dedups by hash,
            // which also keeps the fastblock+GBT double-submit from counting twice.
            if (credit_block(block))
                log::info("BLOCK ACCEPTED (as duplicate; the accepting reply was lost) height={} "
                          "hash={} address={} worker={}",
                          block.height, block.hash, block.address, block.worker);
            else
                log::info("Block {} already known (submitblock: {})", block.hash,
                          rejection.value_or("duplicate"));
            return false;
        case SubmitOutcome::Inconclusive:
            log::warning("Block {} submission was inconclusive", block.hash);
            return true;
        case SubmitOutcome::Rejected:
            log::error("Block {} REJECTED by bitcoind: {}", block.hash,
                       rejection.value_or("unknown"));
            return false;
        }
    } catch (const std::exception& e) {
        log::error("submitblock failed for {}: {}", block.hash, e.what());
    }
    return true;
}

bool Pool::submit_recovered_block(const PendingBlock& block,
                                  const std::filesystem::path& spool_path) {
    const std::string name = spool_path.filename().string();
    try {
        const auto rejection = source_.submit_block_hex(block.hex);
        const SubmitOutcome outcome = classify_submit(rejection);
        std::string suffix;
        if (outcome == SubmitOutcome::Accepted || outcome == SubmitOutcome::AlreadyKnown) {
            log::info("Spooled block {} accepted/already known; archiving", name);
            suffix = ".submitted";
        } else if (outcome == SubmitOutcome::Inconclusive) {
            log::warning("Spooled block {} submission was inconclusive; retrying in {} seconds",
                         name, kInconclusiveRetryDelay.count());
            return true;
        } else {
            log::warning("Spooled block {} rejected by bitcoind ({}); archiving", name,
                         rejection.value_or("unknown"));
            suffix = ".rejected";
        }
        archive_recovered_block(spool_path, suffix);
        return false;
    } catch (const std::exception& error) {
        log::error("Could not resubmit spooled block {} ({}); retrying in {} seconds", name,
                   error.what(), kInconclusiveRetryDelay.count());
    }
    return true;
}

void Pool::archive_recovered_block(const std::filesystem::path& spool_path,
                                   std::string_view suffix) {
    std::error_code error;
    std::filesystem::rename(spool_path, spool_path.string() + std::string(suffix), error);
    if (error)
        log::error("Could not archive spooled block {} ({}); leaving it for the next restart",
                   spool_path.filename().string(), error.message());
}

bool Pool::resolve_recovered_block_from_tip(const PendingBlock& block,
                                            const std::filesystem::path& spool_path) {
    if (block.height < 0 || block.hash.empty())
        return false;

    try {
        const std::string raw_tip_hash = source_.get_tip();
        if (raw_tip_hash.size() != 64 || !util::is_hex(raw_tip_hash))
            return false;
        const std::string tip_hash = util::to_hex(util::from_hex(raw_tip_hash));
        if (block.hash == tip_hash) {
            log::info("Spooled block {} is the active tip; archiving as submitted",
                      spool_path.filename().string());
            archive_recovered_block(spool_path, ".submitted");
            return true;
        }

        const bitcoin::HeaderFacts tip = source_.fetch_header(tip_hash);
        if (tip.confirmations < 1 || block.height >= tip.height)
            return false;

        try {
            const bitcoin::HeaderFacts candidate = source_.fetch_header(block.hash);
            if (candidate.height != block.height)
                return false;
            if (candidate.confirmations > 0) {
                log::info("Spooled block {} is in the active chain; archiving as submitted",
                          spool_path.filename().string());
                archive_recovered_block(spool_path, ".submitted");
                return true;
            }
            if (candidate.confirmations != -1)
                return false;
        } catch (const RpcError& error) {
            if (error.code() != kRpcBlockNotFound)
                throw;
        }

        log::info("Spooled block {} at height {} is below active tip height {}; archiving as stale",
                  spool_path.filename().string(), block.height, tip.height);
        archive_recovered_block(spool_path, ".stale");
        return true;
    } catch (const std::exception& error) {
        log::debug("Could not check whether spooled block {} is stale: {}",
                   spool_path.filename().string(), error.what());
    }
    return false;
}

void Pool::submit_loop(const std::stop_token& stop) {
    while (!stop.stop_requested()) {
        std::shared_ptr<const PendingBlock> block;
        {
            std::unique_lock lock(submit_mutex_);
            if (!submit_cv_.wait(lock, stop, [this] { return !submit_queue_.empty(); }) ||
                stop.stop_requested())
                return;
            block = std::move(submit_queue_.front());
            submit_queue_.pop_front();
        }
        const bool retry = submit_block(*block);
        if (!retry)
            continue;
        {
            const std::scoped_lock lock(recovery_mutex_);
            recovery_queue_.push_back(DeferredSubmission{
                .block = std::move(block),
                .retry_after = std::chrono::steady_clock::now() + kInconclusiveRetryDelay,
            });
        }
        recovery_cv_.notify_one();
    }
}

void Pool::recovery_loop(const std::stop_token& stop) {
    while (auto submission =
               wait_for_submission(recovery_queue_, recovery_mutex_, recovery_cv_, stop)) {
        bool retry = false;
        if (!submission->recovered_spool_path) {
            retry = submit_block(*submission->block);
        } else if (submission->submitted_once &&
                   resolve_recovered_block_from_tip(*submission->block,
                                                    *submission->recovered_spool_path)) {
            retry = false;
        } else {
            retry = submit_recovered_block(*submission->block, *submission->recovered_spool_path);
            submission->submitted_once = true;
        }
        if (!retry || (stop.stop_requested() && submission->recovered_spool_path))
            continue;
        submission->retry_after = std::chrono::steady_clock::now() + kInconclusiveRetryDelay;
        {
            const std::scoped_lock lock(recovery_mutex_);
            recovery_queue_.push_back(std::move(*submission));
        }
        recovery_cv_.notify_one();
    }
}

} // namespace erikslund

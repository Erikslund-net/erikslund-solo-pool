#pragma once
// Polls bitcoind for templates, builds Jobs, broadcasts work, validates addresses, submits
// solved blocks. Implements stratum::PoolContext.
//
// Locks: mutex_ guards the client list; jobs_mutex_ (shared) the current/recent jobs; share
// accounting counters are atomic, pool rate windows have their own mutex, and persistent worker
// rows have per-row mutexes (taken after user_stats_mutex_ when both are needed); per-session state
// has its own mutex. The work thread copies the client list under mutex_ then notifies lock-free,
// never holding two locks.
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "api/snapshot.hpp"
#include "bitcoin/network.hpp"
#include "bitcoin/work_source.hpp"
#include "core/config.hpp"
#include "mining/client.hpp"
#include "stats/hashrate.hpp"
#include "stats/share_accounting.hpp"
#include "stratum/job.hpp"
#include "stratum/session.hpp"

namespace erikslund {

struct PoolTestPeek; // test-only access to the registry prune

namespace sv2 {
class Connection;
class Session;
} // namespace sv2

class Pool : public stratum::PoolContext {
public:
    Pool(Config config, bitcoin::WorkSource& source, uint64_t work_generation);
    ~Pool() override;

    // Set whether bitcoind can currently serve mining work.
    void set_generator_ready(bool ready) { generator_ready_.store(ready); }

    void detect_network();

    void refresh_work(const std::stop_token& stop);

    void vardiff_loop(const std::stop_token& stop);
    void status_loop(const std::stop_token& stop);
    // Call after the server and external pool loops have stopped.
    void shutdown();

    void recover_stats();
    // Queue blocks spooled by a previous run for submission and retry.
    void resubmit_spooled_blocks();

    void notify_new_block();

    std::shared_ptr<stratum::Session> add_client(std::shared_ptr<stratum::Connection> connection);
    std::shared_ptr<sv2::Session> add_sv2_client(std::shared_ptr<sv2::Connection> connection);
    void remove_client(const std::shared_ptr<mining::Client>& session);
    size_t client_count() const;

    void set_connector_ready(bool ready);
    void set_sv2_authenticated_state(
        std::optional<bool> ready,
        std::optional<int64_t> certificate_expiry_timestamp);
    void reload_config(const RuntimeConfig& config);
    void note_config_reload_rejected() noexcept;

    // include_workers samples the persistent per-worker registry into snapshot.workers (an
    // O(registry) walk under user_stats_mutex_). Only the stats-file writer passes true; the HTTP
    // path leaves it false to avoid that cost and per-worker snapshot locking.
    api::PoolSnapshot snapshot(bool include_workers = false) const;
    // Cheap readiness probe for /health (same predicate as PoolSnapshot::ready).
    bool ready() const;

    void on_zmq_block(const std::string& block_hash_display);

    size_t extranonce2_size() const override { return config_.extranonce2_size; }
    std::shared_ptr<const RuntimeConfig> runtime_config() const override {
        return runtime_config_.load();
    }
    std::optional<Bytes> validate_address(const std::string& address) override;
    std::shared_ptr<const stratum::Job> current_job() const override;
    std::shared_ptr<const stratum::Job> recent_job(const std::string& job_id) const override;
    void note_accepted_share(const std::string& address, const std::string& worker, double credited,
                             double share_difficulty) override;
    void note_rejected_share(const std::string& address, const std::string& worker,
                             stratum::RejectClass reason) override;
    void note_accepted_share(const stats::WorkerAccountingHandle& accounting,
                             const std::string& address, const std::string& worker, double credited,
                             double share_difficulty) override;
    void note_rejected_share(const stats::WorkerAccountingHandle& accounting,
                             const std::string& address, const std::string& worker,
                             stratum::RejectClass reason) override;
    stats::WorkerAccountingHandle attach_worker(const std::string& address,
                                                const std::string& worker) override;
    // Seed the per-worker registry from a prior run's users/ files, decaying each worker's hashrate
    // windows by the file's age. Call once at startup before serving.
    void recover_user_stats();
    void on_block_found(const std::string& address, const std::string& worker,
                        const stratum::Job& job,
                        const stratum::ShareResult& result) override;
    uint32_t version_mask() const override { return config_.version_rolling_mask; }

    uint64_t accepted_shares() const { return accepted_shares_.load(); }
    uint64_t blocks_found() const { return blocks_found_.load(); }
    bitcoin::Network network() const { return network_; }

    std::string next_job_id();

private:
    enum class AuthenticatedSv2State : int8_t {
        Disabled,
        Unavailable,
        Ready,
    };
    static constexpr int64_t kUnknownCertificateExpiry = -1;

    struct ConnectedClient {
        std::shared_ptr<mining::Connection> connection;
        std::shared_ptr<mining::Client> session;
        bool publish_asynchronously = false;
    };
    struct PendingPublication {
        std::shared_ptr<ConnectedClient> recipient;
        std::shared_ptr<const stratum::Job> job;
        bool clean = false;
    };

    struct PendingBlock {
        int64_t height;
        std::string hash;
        std::string hex;
        std::string address;
        std::string worker;
    };

    struct DeferredSubmission {
        std::shared_ptr<const PendingBlock> block;
        std::optional<std::filesystem::path> recovered_spool_path = std::nullopt;
        bool submitted_once = false;
        std::chrono::steady_clock::time_point retry_after{};
    };

    // Both take the template BY VALUE and move it into the Job, which steals the multi-MB tx blob.
    void build_and_broadcast(bitcoin::BlockTemplate block_template, bool clean);
    std::shared_ptr<stratum::Job> make_job(bitcoin::BlockTemplate block_template, bool clean);
    enum class PublishOutcome { Published, Duplicate, StaleHeight, StalePrevhash };
    PublishOutcome broadcast_job(const std::shared_ptr<const stratum::Job>& job, bool clean,
                                 bool require_new_prevhash = false);
    void enqueue_publication(
        const std::shared_ptr<ConnectedClient>& recipient,
        const std::shared_ptr<const stratum::Job>& job, bool clean);
    void publication_loop(const std::stop_token& stop);
    Bytes next_extranonce1();
    void write_stats();
    void stop_workers();
    void spool_block(const PendingBlock& block);

    Config config_;
    const uint64_t work_generation_;
    bitcoin::WorkSource& source_;
    std::atomic<std::shared_ptr<const RuntimeConfig>> runtime_config_;
    bitcoin::Network network_ = bitcoin::Network::Regtest;
    std::string chain_name_ = "regtest";
    Bytes donation_script_;

    // mutex_ guards: clients_, blocks_by_address_, last_prevhash_, and the template bookkeeping
    // below (has_template_/last_template_time_/last_version_). blocks_by_address_
    // and last_prevhash_ are under mutex_, NOT jobs_mutex_, despite sitting next to its fields.
    mutable std::mutex mutex_;
    std::vector<std::shared_ptr<ConnectedClient>> clients_;
    // jobs_mutex_ (shared) guards ONLY the job cache: current_job_, recent_jobs_, recent_order_,
    // publish_counter_.
    mutable std::shared_mutex jobs_mutex_;
    std::shared_ptr<const stratum::Job> current_job_;
    std::map<std::string, std::shared_ptr<const stratum::Job>> recent_jobs_;
    std::deque<std::string> recent_order_;
    uint64_t publish_counter_ = 0; // publication order stamped onto each published job
    std::map<std::string, uint64_t> blocks_by_address_; // guarded by mutex_ (not jobs_mutex_)
    std::set<std::string> credited_blocks_;             // block hashes already counted (mutex_)
    std::string last_prevhash_;                         // guarded by mutex_ (not jobs_mutex_)

    std::atomic<uint64_t> job_counter_{0};
    uint32_t job_id_prefix_ = 0;
    std::atomic<uint64_t> extranonce1_counter_{0};
    std::atomic<uint64_t> broadcast_cursor_{0};
    std::atomic<uint64_t> accepted_shares_{0};
    std::array<std::atomic<uint64_t>, stratum::kRejectClassCount> rejected_by_class_{};
    std::atomic<uint64_t> blocks_found_{0};
    std::atomic<int64_t> last_block_found_{0}; // wall epoch of the most recent accepted block

    std::atomic<bool> generator_ready_{false};
    std::atomic<bool> connector_ready_{false};
    std::atomic<AuthenticatedSv2State> sv2_authenticated_state_{
        AuthenticatedSv2State::Disabled};
    std::atomic<int64_t> sv2_certificate_expiry_timestamp_{
        kUnknownCertificateExpiry};
    std::atomic<int64_t> chain_blocks_{-1};
    std::atomic<uint64_t> config_generation_{0};
    std::atomic<bool> last_reload_rejected_{false};
    int64_t started_ = 0;
    double started_steady_ = 0.0;

    double last_template_time_ = 0.0;
    std::atomic<double> total_share_difficulty_{0.0};
    double baseline_difficulty_ = 0.0;
    double baseline_best_difficulty_ = 0.0;
    // Pool-wide best share (actual hash difficulty), ratcheted monotonically on every accepted
    // share so snapshot() does not depend on retained worker rows.
    std::atomic<double> best_difficulty_runtime_{0.0};

    mutable std::mutex stats_mutex_; // guards the two DecayingWindows below
    stats::DecayingWindows<stats::kHashrateWindows.size()> hashrate_windows_;
    stats::DecayingWindows<stats::kSpsWindows.size()> sps_windows_;

    using WorkerMap = std::map<std::string, stats::WorkerAccountingHandle>;
    mutable std::mutex user_stats_mutex_;
    std::map<std::string, WorkerMap> user_stats_; // address -> worker
    stats::WorkerAccountingHandle worker_entry(const std::string& address,
                                               const std::string& worker);
    std::string resolve_worker_key(const WorkerMap& workers, const std::string& worker) const;
    void prune_user_stats(int64_t now);
    friend struct PoolTestPeek;

    bool has_template_ = false;
    uint32_t last_version_ = 0;
    std::string empty_commitment_;

    std::atomic<double> last_broadcast_steady_{0.0};

    std::mutex wakeup_mutex_;
    std::condition_variable_any wakeup_cv_;
    bool new_block_flag_ = false;

    bool credit_block(const PendingBlock& block);
    [[nodiscard]] bool submit_block(const PendingBlock& block);
    [[nodiscard]] bool submit_recovered_block(const PendingBlock& block,
                                              const std::filesystem::path& spool_path);
    void archive_recovered_block(const std::filesystem::path& spool_path,
                                 std::string_view suffix);
    [[nodiscard]] bool resolve_recovered_block_from_tip(
        const PendingBlock& block, const std::filesystem::path& spool_path);
    void submit_loop(const std::stop_token& stop);
    std::mutex submit_mutex_;
    std::condition_variable_any submit_cv_;
    std::deque<std::shared_ptr<const PendingBlock>> submit_queue_;

    void recovery_loop(const std::stop_token& stop);
    std::mutex recovery_mutex_;
    std::condition_variable_any recovery_cv_;
    std::deque<DeferredSubmission> recovery_queue_;
    std::set<std::filesystem::path> tracked_recovered_blocks_;

    std::mutex publication_mutex_;
    std::condition_variable_any publication_cv_;
    std::deque<PendingPublication> publication_queue_;

    std::jthread submit_thread_;
    std::jthread recovery_thread_;
    std::jthread publication_thread_;
};

// Whether one-block-ahead empty work is sound for the notified tip. confirmations == 1 (from
// getblockheader) proves the notified hash IS the active tip now; >= 2 or -1 would build on a
// superseded parent. Pure (exposed for tests).
bool fastblock_eligible(bool has_template, const std::string& notified_tip,
                        const std::string& last_prevhash, int64_t next_height,
                        int64_t confirmations, const std::string& chain_name,
                        const std::string& bits_hex);

// Consensus GetBlockSubsidy: 50 BTC halved every `halving_interval`, zero after 64 halvings.
uint64_t block_subsidy(int64_t height, int64_t halving_interval);

} // namespace erikslund

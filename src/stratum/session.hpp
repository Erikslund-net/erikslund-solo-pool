#pragma once
// One Session per TCP connection: per-connection protocol state, reaching the pool
// through the Connection and PoolContext interfaces.
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "core/config.hpp"
#include "mining/client.hpp"
#include "stats/share_accounting.hpp"
#include "stratum/job.hpp"
#include "stratum/message.hpp"
#include "util/bytes.hpp"

namespace erikslund::stratum {

inline constexpr size_t kMaxSeenShares = 16384;

struct SessionTestPeek; // test-only access to dedup and control-rate state

// Outbound side of a connection (socket in prod, recorder in tests).
class Connection : public virtual mining::Connection {
public:
    virtual ~Connection() = default;
    virtual void send_line(std::string_view line) = 0;
    virtual void send_lines(std::span<const std::string_view> lines) {
        for (std::string_view line : lines)
            send_line(line);
    }
};

// Everything a session needs from the pool. Implemented by Pool; faked in tests.
class PoolContext {
public:
    virtual ~PoolContext() = default;
    virtual size_t extranonce2_size() const = 0;
    virtual std::shared_ptr<const RuntimeConfig> runtime_config() const = 0;
    // Payout scriptPubKey for an address, or nullopt if it's invalid.
    virtual std::optional<Bytes> validate_address(const std::string& address) = 0;
    virtual std::shared_ptr<const Job> current_job() const = 0;
    virtual std::shared_ptr<const Job> recent_job(const std::string& job_id) const = 0;
    // Share accounting carries the worker identity for persistent per-worker stats (users/ files).
    // `credited` is the difficulty credited (shares/hashrate); `share_difficulty` is the ACTUAL
    // hash difficulty met (for the per-worker best-share).
    virtual void note_accepted_share(const std::string& address, const std::string& worker,
                                     double credited, double share_difficulty) = 0;
    virtual void note_rejected_share(const std::string& address, const std::string& worker,
                                     RejectClass reason) = 0;
    virtual void note_accepted_share(const stats::WorkerAccountingHandle& accounting,
                                     const std::string& address, const std::string& worker,
                                     double credited, double share_difficulty) {
        (void)accounting;
        note_accepted_share(address, worker, credited, share_difficulty);
    }
    virtual void note_rejected_share(const stats::WorkerAccountingHandle& accounting,
                                     const std::string& address, const std::string& worker,
                                     RejectClass reason) {
        (void)accounting;
        note_rejected_share(address, worker, reason);
    }
    // Called on a successful authorize so an idle authorized worker appears in (and persists in)
    // the registry with zero stats.
    virtual stats::WorkerAccountingHandle attach_worker(const std::string& address,
                                                        const std::string& worker) {
        (void)address;
        (void)worker;
        return {};
    }
    virtual void on_block_found(const std::string& address, const std::string& worker,
                                const Job& job, const ShareResult& result) = 0;

    virtual uint32_t version_mask() const = 0;
};

class Session : public mining::Client {
public:
    Session(PoolContext& pool, Connection& connection, Bytes extranonce1);

    // Feed one decoded line (no trailing newline). Thread-safe.
    void handle_line(std::string_view line);

    // Thread-safe: work thread pushes work while the read thread may be in a submit.
    void send_set_difficulty();
    void send_notify(const Job& job, bool clean);
    void publish_job(const Job& job, bool clean) override { send_notify(job, clean); }

    // Thread-safe; called periodically by the pool's vardiff loop.
    void maybe_retarget() override;

    bool subscribed() const { return subscribed_; }
    bool authorized() const { return authorized_; }
    bool ever_authorized() const override { return authorized_; }
    int protocol_errors() const override { return protocol_errors_; }
    bool should_close() const override { return close_requested_.load(std::memory_order_relaxed); }
    const std::string& extranonce1_hex() const { return extranonce1_hex_; }
    double difficulty() const { return difficulty_; }
    uint32_t version_mask() const { return version_mask_; }
    const std::optional<std::string>& address() const { return address_; }
    const std::optional<std::string>& worker() const { return worker_; }
    const std::string& user_agent() const { return user_agent_; }
    uint64_t shares_accepted() const { return shares_accepted_; }
    double best_difficulty() const { return best_difficulty_; }
    std::string peer() const { return connection_.peer(); }

    // Thread-safe snapshot of this session's stats (for the HTTP API).
    mining::ClientStats stats(bool include_worker_accounting = false) const override;

private:
    bool allow_control_request(std::chrono::steady_clock::time_point now);
    void dispatch(const Request& request);
    void handle_subscribe(const glz::generic& id, const std::vector<std::string>& params);
    void handle_configure(const Request& request);
    void handle_authorize(const glz::generic& id, const std::vector<std::string>& params);
    void handle_submit(const glz::generic& id, const std::vector<std::string>& params);
    void handle_suggest_difficulty(const Request& request);

    // Caller holds mutex_; the public send_* wrap these.
    void do_send_set_difficulty();
    std::string set_difficulty_line();
    std::optional<std::string> build_notify_line(const Job& job, bool clean);
    void send_difficulty_then_work();

    void begin_difficulty_change(double new_difficulty);

    void send(const glz::generic& message);
    void send_result(const glz::generic& id, glz::generic result);
    void send_result(const glz::generic& id, bool result); // fast path: straight to the wire
    void send_error(const glz::generic& id, const StratumError& error);

    // Different wire spellings of the same header share one key.
    std::string make_dedup_key(const Job& job, std::string_view extranonce2,
                               std::string_view ntime, std::string_view nonce,
                               const std::optional<std::string>& version_bits) const;
    void record_accepted_share_locked(double credited, double share_difficulty);

    // Caches one job's coinbase2 bytes+hex so mining.notify doesn't re-encode per broadcast.
    struct Coinbase2Cache {
        std::string job_id;
        Bytes coinbase2;
        std::string coinbase2_hex;
    };
    std::shared_ptr<const Coinbase2Cache> coinbase2_for(const Job& job);
    bool remember(std::string key);

    friend struct SessionTestPeek;

    PoolContext& pool_;
    Connection& connection_;

    Bytes extranonce1_;
    std::string extranonce1_hex_;

    bool subscribed_ = false;
    bool authorized_ = false;
    int protocol_errors_ = 0; // client-misbehaviour errors counted toward the disconnect budget
    // Control traffic gets a separate budget: accepted shares must not replenish it.
    static constexpr double kControlRequestBurst = 16.0;
    static constexpr double kControlRequestsPerSecond = 1.0;
    double control_request_tokens_ = kControlRequestBurst;
    std::chrono::steady_clock::time_point control_refill_at_ = std::chrono::steady_clock::now();
    std::atomic<bool> close_requested_{false};
    std::optional<std::string> address_;
    std::optional<std::string> worker_;
    std::optional<Bytes> payout_script_;
    stats::WorkerAccountingHandle worker_accounting_;

    double difficulty_;
    double previous_difficulty_ = 0.0;
    bool pending_difficulty_change_ = false;
    int64_t connected_at_ = 0;          // wall epoch: DISPLAYED
    double connected_at_steady_ = 0.0;  // monotonic: decay clock + connected_seconds
    int64_t last_share_timestamp_ = 0;  // wall epoch: DISPLAYED
    double last_retarget_ = 0.0;        // monotonic: retarget interval is a duration
    uint64_t shares_since_retarget_ = 0;
    uint32_t version_mask_ = 0;
    std::string user_agent_ = "?";

    uint64_t shares_accepted_ = 0;
    uint64_t shares_rejected_ = 0;
    double best_difficulty_ = 0.0;
    double total_share_difficulty_ = 0.0;
    // Decaying diff/s per window. Guarded by mutex_ (written on share, read in stats()).
    stats::DecayingWindows<stats::kHashrateWindows.size()> hashrate_;

    std::shared_ptr<const Coinbase2Cache> coinbase2_cache_; // replaced under mutex_; see above
    std::unordered_set<std::string> seen_shares_current_;
    std::unordered_set<std::string> seen_shares_previous_;
    void rotate_seen_shares();
    // Highest pool publication delivered; sequence 0 is an unstamped direct job.
    uint64_t last_notified_publication_sequence_ = 0;
    // Reused response-line buffer for the per-share ack/error fast paths (guarded by mutex_);
    // capacity persists so steady-state responses allocate nothing.
    std::string response_scratch_;

    mutable std::mutex mutex_; // serializes handle_line vs. send_* across threads
};

// Pure vardiff decision (exposed for testing). New difficulty clamped to [min, max];
// max 0 = no maximum (defaults to 1e12).
double vardiff_next(double current, double shares_per_minute, double target,
                    double min_difficulty, double max_difficulty);

std::optional<double> clamp_suggested_difficulty(double suggested, double min_difficulty,
                                                 double max_difficulty);

} // namespace erikslund::stratum

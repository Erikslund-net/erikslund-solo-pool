#pragma once
// SV2 Mining Channel state machine, independent of its ordered transport.
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "mining/client.hpp"
#include "stats/hashrate.hpp"
#include "stratum/session.hpp"
#include "sv2/codec.hpp"
#include "sv2/connection.hpp"
#include "sv2/messages.hpp"
#include "util/uint256.hpp"

namespace erikslund::sv2 {

inline constexpr std::chrono::milliseconds kStandardJobRefreshInterval{250};

class Session final : public mining::Client {
public:
    Session(stratum::PoolContext& pool, Connection& connection, Bytes extranonce1,
            uint32_t maximum_payload_size = 16384);

    void handle_bytes(ByteView bytes);
    void publish_job(const stratum::Job& job, bool clean) override;
    void maybe_retarget() override;
    void maybe_refresh_job();
    mining::ClientStats stats(bool include_worker_accounting = false) const override;

    bool authorized() const;
    bool ever_authorized() const override;
    int protocol_errors() const override;
    bool should_close() const override;

private:
    enum class ChannelKind : uint8_t {
        Standard,
        Extended,
    };

    struct IssuedJob {
        std::shared_ptr<const stratum::Job> source_job;
        std::variant<stratum::StandardWork, stratum::ExtendedWork> work;
        Bytes extranonce_prefix;
        std::size_t extranonce_size{};
        util::uint256 target;
        uint32_t minimum_ntime{};
        uint32_t previous_hash_minimum_ntime{};
        double previous_hash_received_at_steady{};
        bool follows_channel_target = false;
    };
    struct JobBuildPlan {
        uint32_t channel_id{};
        ChannelKind kind{};
        std::shared_ptr<const stratum::Job> source_job;
        Bytes payout_script;
        Bytes extranonce_prefix;
        std::size_t extranonce_size{};
        uint32_t job_id{};
        bool announce_extranonce_prefix = false;
        std::variant<stratum::StandardWork, stratum::ExtendedWork> work;
    };

    struct ShareKey {
        uint32_t channel_id{};
        uint32_t job_id{};
        uint32_t nonce{};
        uint32_t ntime{};
        uint32_t version{};
        Bytes extranonce;
        friend bool operator==(const ShareKey&, const ShareKey&) = default;
    };
    struct ShareKeyHash {
        std::size_t operator()(const ShareKey& key) const noexcept;
    };
    struct FoundBlock {
        std::shared_ptr<const stratum::Job> source_job;
        stratum::ShareResult result;
        std::string address;
        std::string worker;
    };
    struct ShareSubmission {
        ChannelKind kind;
        uint32_t channel_id{};
        uint32_t sequence_number{};
        uint32_t job_id{};
        uint32_t nonce{};
        uint32_t ntime{};
        uint32_t version{};
        ByteView extranonce;
    };
    struct PreparedShare {
        std::shared_ptr<IssuedJob> issued_job;
        Bytes submitted_extranonce;
        util::uint256 issued_target;
        uint32_t version_rolling_mask{};
        stats::WorkerAccountingHandle worker_accounting;
        std::string address;
        std::string worker;
    };
    struct ShareValidation {
        std::expected<stratum::ShareResult, stratum::ShareRejection> result;
        double credited_difficulty{};
    };
    struct Channel {
        Channel(uint32_t channel_id, ChannelKind channel_kind,
                double opened_at)
            : id(channel_id),
              kind(channel_kind),
              opened_at_steady(opened_at),
              last_retarget_at_steady(opened_at),
              hashrate(std::span<const int, stats::kHashrateWindows.size()>(
                           stats::kHashrateWindows),
                       opened_at) {}

        uint32_t id{};
        ChannelKind kind{};
        std::string address;
        std::string worker;
        Bytes payout_script;
        stats::WorkerAccountingHandle worker_accounting;
        Bytes extranonce_prefix;
        std::size_t extranonce_size{};
        util::uint256 device_maximum_target;
        util::uint256 target;
        double difficulty{};
        uint64_t last_publication_sequence{};
        bool requires_frequent_job_refresh = false;
        double opened_at_steady{};
        double last_retarget_at_steady{};
        uint64_t shares_since_retarget{};
        uint64_t shares_accepted{};
        uint64_t shares_rejected{};
        double total_share_difficulty{};
        double best_difficulty{};
        int64_t last_share_timestamp{};
        stats::DecayingWindows<stats::kHashrateWindows.size()> hashrate;
        std::deque<std::pair<uint32_t, std::shared_ptr<IssuedJob>>> jobs;
        Bytes previous_hash;
        uint32_t previous_bits{};
        uint32_t previous_hash_minimum_ntime{};
        double previous_hash_received_at_steady{};
    };

    void dispatch_locked(const Frame& frame, std::unique_lock<std::mutex>& lock);
    void handle_setup_locked(const SetupConnection& message);
    void handle_open_locked(const OpenStandardMiningChannel& message);
    void handle_open_locked(const OpenExtendedMiningChannel& message);
    void open_channel_locked(uint32_t request_id, std::string_view user_identity,
                             float nominal_hash_rate, const U256& maximum_target,
                             ChannelKind kind);
    void handle_update_locked(const UpdateChannel& message);
    void handle_close_locked(const CloseChannel& message);
    void handle_submit_locked(const SubmitSharesStandard& message,
                              std::unique_lock<std::mutex>& lock);
    void handle_submit_locked(const SubmitSharesExtended& message,
                              std::unique_lock<std::mutex>& lock);
    void handle_share_locked(const ShareSubmission& share,
                             std::unique_lock<std::mutex>& lock);
    std::optional<PreparedShare> prepare_share_locked(
        const ShareSubmission& share);
    ShareValidation validate_and_account_share(
        const ShareSubmission& share, const PreparedShare& prepared);
    void finish_share_locked(const ShareSubmission& share,
                             const PreparedShare& prepared,
                             ShareValidation&& validation);
    void issue_job_locked(
        Channel& channel, const std::shared_ptr<const stratum::Job>& job,
        bool clean,
        std::optional<Bytes> announced_prefix = std::nullopt);
    JobBuildPlan prepare_job_locked(
        Channel& channel, const std::shared_ptr<const stratum::Job>& job,
        std::optional<Bytes> announced_prefix = std::nullopt);
    static void build_job_work(JobBuildPlan& plan);
    void commit_job_locked(Channel& channel, JobBuildPlan&& plan, bool clean);

    Bytes allocate_extranonce_prefix_locked();
    uint32_t allocate_job_id_locked();
    void rotate_share_history_for_clean_job_locked(
        const std::shared_ptr<const stratum::Job>& job);
    bool remember_share_locked(const ShareKey& key);
    void send_share_rejection_locked(Channel* channel, const ShareSubmission& share,
                                     const std::string& address,
                                     std::string error_code);
    void reject_share_locked(Channel* channel, const ShareSubmission& share,
                             std::string error_code,
                             stratum::RejectClass reason);
    void record_accepted_locked(Channel* channel,
                                double credited_difficulty,
                                double share_difficulty);
    double job_hashes(ChannelKind kind) const;
    double maximum_hash_rate(ChannelKind kind) const;
    double difficulty_for_hashrate(float nominal_hash_rate,
                                   const RuntimeConfig& config) const;
    void update_job_refresh_requirement_locked(Channel& channel,
                                               float nominal_hash_rate);
    bool requires_new_prevhash_locked(const Channel& channel,
                                      const stratum::Job& job) const;
    void change_target_locked(Channel& channel, const util::uint256& new_target);
    void send_locked(ByteView bytes);

    stratum::PoolContext& pool_;
    Connection& connection_;
    FrameDecoder decoder_;
    Bytes extranonce1_;
    uint64_t extranonce_counter_{};
    uint32_t next_channel_id_ = 1;
    uint32_t next_job_id_ = 1;
    std::optional<ChannelKind> channel_kind_;

    bool setup_complete_ = false;
    uint32_t requested_setup_flags_{};
    bool ever_authorized_ = false;
    bool close_after_response_ = false;
    int protocol_errors_ = 0;
    std::string user_agent_ = "?";

    uint32_t version_mask_{};
    std::map<uint32_t, Channel> channels_;
    std::weak_ptr<const stratum::Job> last_clean_job_;
    uint64_t last_clean_publication_sequence_{};
    std::unordered_set<ShareKey, ShareKeyHash> seen_shares_;
    std::unordered_set<ShareKey, ShareKeyHash> seen_shares_previous_;
    std::vector<FoundBlock> pending_blocks_;

    int64_t connected_at_{};
    double connected_at_steady_{};
    int64_t last_share_timestamp_{};
    uint64_t shares_accepted_{};
    uint64_t shares_rejected_{};
    double total_share_difficulty_{};
    double best_difficulty_{};
    stats::DecayingWindows<stats::kHashrateWindows.size()> hashrate_;

    mutable std::mutex mutex_;
    friend struct SessionTestPeek;
};

} // namespace erikslund::sv2

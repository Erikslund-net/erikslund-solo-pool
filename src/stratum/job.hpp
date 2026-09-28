#pragma once
// One block template as mineable work + share validation. Per-template state is shared;
// coinbase2 (payout) is per miner. Immutable + pure validate_share().
#include <array>
#include <atomic>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "bitcoin/block_template.hpp"
#include "util/block_header.hpp"
#include "util/bytes.hpp"
#include "util/sha256.hpp"
#include "util/uint256.hpp"

namespace erikslund::stratum {

// Why a share was rejected; reject_reason() maps it to a stable human string for logs.
enum class ShareReject : uint8_t {
    None,
    InvalidExtranonce2Size,
    MalformedField,
    NtimeOutOfRange,
    MalformedVersionBits,
    VersionRollingNotNegotiated,
    VersionBitsOutsideMask,
    AboveTarget,
};

std::string_view reject_reason(ShareReject reject);

enum class RejectClass : uint8_t {
    Stale,         // job not found: churn / miner lagging behind notifies
    Duplicate,     // dedup hit: firmware resubmitting
    Malformed,     // oversize or unparseable fields: broken firmware / garbage
    Ntime,         // ntime out of range: clock drift
    Version,       // version-rolling negotiation / mask violations
    LowDifficulty, // above target: difficulty config mismatch
};
inline constexpr size_t kRejectClassCount = 6;

std::string_view reject_class_label(RejectClass cls); // "stale", "duplicate", ... (metric labels)
RejectClass reject_class_of(ShareReject reject);      // fine-grained reason -> coarse class

struct ShareRejection {
    ShareReject reason = ShareReject::None;
    double difficulty = 0.0;
};

struct ShareResult {
    double difficulty = 0.0;             // pool difficulty this hash satisfies
    bool is_block = false;               // hash <= network target
    std::array<uint8_t, util::kHeaderSize> header{};    // fixed-size: no per-share heap traffic
    Bytes legacy_coinbase;
    // Canonical (display) hash as hex. Stored inline (a submit-rate path frees a heap string
    // unread on every non-block share otherwise); read through the accessor.
    std::array<char, 64> block_hash_chars{};
    std::string_view block_hash_hex() const {
        return {block_hash_chars.data(), block_hash_chars.size()};
    }
};

struct ShareInput {
    ByteView coinbase2;
    ByteView extranonce1;
    std::string_view extranonce2_hex;
    std::string_view ntime_hex;
    std::string_view nonce_hex;
    util::uint256 share_target;
    std::optional<std::string> version_bits_hex;
    uint32_t version_mask = 0;
    int64_t now_unix = 0;
};

// Version bits an SV2 device may roll whenever version rolling is allowed: BIP323's
// general-purpose bits, which the SV2 Mining Protocol references. SV1 negotiates its own mask.
inline constexpr uint32_t kSv2VersionRollingMask = 0x1fffffe0;

struct StandardWork {
    Bytes legacy_coinbase;
    util::Hash256 merkle_root{};
};

struct ExtendedWork {
    Bytes coinbase_tx_prefix;
    Bytes coinbase_tx_suffix;
    std::vector<util::Hash256> merkle_path;
};

struct StandardShareInput {
    ByteView legacy_coinbase;
    util::Hash256 merkle_root{};
    uint32_t ntime = 0;
    uint32_t nonce = 0;
    uint32_t version = 0;
    uint32_t version_mask = kSv2VersionRollingMask;
    util::uint256 share_target;
    int64_t now_unix = 0;
};

struct ExtendedShareInput {
    ByteView extranonce_prefix;
    ByteView extranonce;
    size_t extranonce_size = 0;
    uint32_t ntime = 0;
    uint32_t nonce = 0;
    uint32_t version = 0;
    uint32_t version_mask = kSv2VersionRollingMask;
    util::uint256 share_target;
    int64_t now_unix = 0;
};

class Job {
public:
    // Takes the template BY VALUE: its multi-MB tx blob is moved out, so callers pass an rvalue.
    Job(std::string job_id, bitcoin::BlockTemplate block_template, ByteView tag,
        size_t extranonce1_size, size_t extranonce2_size, uint32_t coinbase_version,
        bool clean = true, ByteView donation_script = {}, double donation_percent = 0.0,
        ByteView work_identifier = {});

    // mining.notify fields.
    const std::string& job_id() const { return job_id_; }
    const std::string& prevhash_stratum() const { return prevhash_stratum_; }
    const std::string& coinbase1_hex() const { return coinbase1_hex_; }
    const std::vector<std::string>& merkle_branch_hex() const { return merkle_branch_hex_; }
    const std::string& version_hex() const { return version_hex_; }
    const std::string& nbits_hex() const { return nbits_hex_; }
    const std::string& ntime_hex() const { return ntime_hex_; }
    uint32_t version() const { return version_; }
    uint32_t curtime() const { return curtime_; }
    uint32_t bits() const { return bits_; }
    const Bytes& prevhash_internal() const { return prevhash_internal_; }
    bool clean() const { return clean_; }
    int64_t height() const { return height_; }
    int txn_count() const { return static_cast<int>(txn_count_); }
    double network_difficulty() const;

    // True if this job mines on top of `tip_display_hex` (display-order hash from bitcoind).
    bool mines_on(const std::string& tip_display_hex) const;

    // Source-template identity; excludes wire handles and the per-job work identifier.
    const std::string& work_signature() const { return work_signature_; }

    Bytes build_coinbase2(ByteView payout_script) const;
    StandardWork build_standard_work(ByteView payout_script, ByteView extranonce_prefix) const;
    ExtendedWork build_extended_work(ByteView payout_script) const;

    uint64_t publication_sequence() const {
        return publication_sequence_.load(std::memory_order_relaxed);
    }
    void set_publication_sequence(uint64_t sequence) const {
        publication_sequence_.store(sequence, std::memory_order_relaxed);
    }

    // Pure; every field is treated as untrusted.
    [[nodiscard]] std::expected<ShareResult, ShareRejection> validate_share(const ShareInput& input) const;
    [[nodiscard]] std::expected<ShareResult, ShareRejection>
    validate_standard_share(const StandardShareInput& input) const;
    [[nodiscard]] std::expected<ShareResult, ShareRejection>
    validate_extended_share(const ExtendedWork& work, const ExtendedShareInput& input) const;

    std::string build_block_hex(ByteView legacy_coinbase, ByteView header) const;

private:
    std::array<uint8_t, util::kHeaderSize> build_header(const util::Hash256& merkle_root, uint32_t ntime,
                                         uint32_t nonce, uint32_t version) const;
    std::expected<ShareResult, ShareRejection>
    validate_header(Bytes legacy_coinbase, const util::Hash256& merkle_root, uint32_t ntime,
                    uint32_t nonce, uint32_t version, const util::uint256& share_target) const;

    std::string job_id_;
    bool clean_;
    int64_t height_;
    uint32_t version_;
    uint32_t curtime_;
    uint32_t bits_;
    uint64_t coinbase_value_;
    util::uint256 network_target_;

    Bytes prevhash_internal_;
    std::string prevhash_stratum_;
    uint32_t coinbase_sequence_;
    uint32_t coinbase_lock_time_;
    std::optional<Bytes> coinbase_witness_;
    std::vector<bitcoin::CoinbaseOutput> coinbase_required_outputs_;

    Bytes tag_;
    size_t extranonce_size_;
    size_t extranonce2_size_;
    Bytes donation_script_;
    double donation_percent_ = 0.0;

    uint32_t txn_count_;
    Bytes txn_data_;
    std::vector<util::Hash256> merkle_branch_;
    std::vector<std::string> merkle_branch_hex_;

    Bytes coinbase1_;
    std::string coinbase1_hex_;
    std::string version_hex_;
    std::string nbits_hex_;
    std::string ntime_hex_;
    std::string work_signature_;

    mutable std::atomic<uint64_t> publication_sequence_{0};
};

} // namespace erikslund::stratum

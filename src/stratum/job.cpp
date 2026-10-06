#include "stratum/job.hpp"

#include <algorithm>
#include <array>
#include <expected>
#include <format>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

#include "bitcoin/coinbase.hpp"
#include "util/difficulty.hpp"
#include "util/endian.hpp"
#include "util/hex.hpp"
#include "util/merkle.hpp"
#include "util/varint.hpp"

namespace erikslund::stratum {

namespace {

constexpr int64_t kNtimeSlack = 7200;
constexpr int64_t kNtimeSubmitMargin = 120;
constexpr size_t kMaximumDirectPushSize = 75;
constexpr uint8_t kOpPushData1 = 0x4c;

std::unexpected<ShareRejection> rejected(ShareReject reason) {
    return std::unexpected(ShareRejection{reason});
}

// Display hex -> mining.notify form: internal hash with each 4-byte word byte-reversed.
std::string prevhash_to_stratum(const std::string& display_hex) {
    const Bytes internal = util::reversed(util::from_hex(display_hex));
    if (internal.size() != 32)
        throw std::invalid_argument("previousblockhash is not 32 bytes");
    Bytes out;
    out.reserve(32);
    for (size_t word = 0; word < 32; word += 4)
        for (int byte = 3; byte >= 0; --byte)
            out.push_back(internal[word + static_cast<size_t>(byte)]);
    return util::to_hex(out);
}

} // namespace

std::string_view reject_reason(ShareReject reject) {
    switch (reject) {
    case ShareReject::None: return "ok";
    case ShareReject::InvalidExtranonce2Size: return "invalid extranonce2 size";
    case ShareReject::MalformedField: return "malformed share field";
    case ShareReject::NtimeOutOfRange: return "ntime out of range";
    case ShareReject::MalformedVersionBits: return "malformed version bits";
    case ShareReject::VersionRollingNotNegotiated: return "version rolling not negotiated";
    case ShareReject::VersionBitsOutsideMask: return "version bits outside negotiated mask";
    case ShareReject::AboveTarget: return "above target";
    }
    return "unknown";
}

std::string_view reject_class_label(RejectClass cls) {
    switch (cls) {
    case RejectClass::Stale: return "stale";
    case RejectClass::Duplicate: return "duplicate";
    case RejectClass::Malformed: return "malformed";
    case RejectClass::Ntime: return "ntime";
    case RejectClass::Version: return "version";
    case RejectClass::LowDifficulty: return "low_difficulty";
    }
    return "malformed";
}

RejectClass reject_class_of(ShareReject reject) {
    switch (reject) {
    case ShareReject::NtimeOutOfRange: return RejectClass::Ntime;
    case ShareReject::MalformedVersionBits:
    case ShareReject::VersionRollingNotNegotiated:
    case ShareReject::VersionBitsOutsideMask: return RejectClass::Version;
    case ShareReject::AboveTarget: return RejectClass::LowDifficulty;
    case ShareReject::None: // not a reject; unreachable from a validation failure
    case ShareReject::InvalidExtranonce2Size:
    case ShareReject::MalformedField: return RejectClass::Malformed;
    }
    return RejectClass::Malformed;
}

Job::Job(std::string job_id, bitcoin::BlockTemplate block_template, ByteView tag,
         size_t extranonce1_size, size_t extranonce2_size, uint32_t coinbase_version, bool clean,
         ByteView donation_script, double donation_percent, ByteView work_identifier)
    : job_id_(std::move(job_id)),
      clean_(clean),
      height_(block_template.height),
      version_(block_template.version),
      curtime_(block_template.curtime),
      bits_(block_template.bits),
      coinbase_value_(block_template.coinbase_value),
      network_target_(util::target_from_compact(block_template.bits)),
      maximum_share_difficulty_(util::maximum_difficulty_for_target(network_target_)),
      prevhash_internal_(util::reversed(util::from_hex(block_template.previousblockhash))),
      prevhash_stratum_(prevhash_to_stratum(block_template.previousblockhash)),
      coinbase_sequence_(block_template.coinbase_sequence),
      coinbase_lock_time_(block_template.coinbase_lock_time),
      coinbase_witness_(std::move(block_template.coinbase_witness)),
      coinbase_required_outputs_(std::move(block_template.coinbase_required_outputs)),
      tag_(tag.begin(), tag.end()),
      extranonce_size_(extranonce1_size + extranonce2_size),
      extranonce2_size_(extranonce2_size),
      txn_count_(block_template.txn_count),
      // Steal the concatenated tx blob (multi-MB on mainnet) -- the point of taking by value.
      txn_data_(std::move(block_template.txn_data)),
      nbits_hex_(std::move(block_template.bits_hex)) {
    donation_script_.assign(donation_script.begin(), donation_script.end());
    donation_percent_ = donation_percent;

    merkle_branch_ = std::move(block_template.merkle_branch_internal);
    merkle_branch_hex_.reserve(merkle_branch_.size());
    for (const auto& node : merkle_branch_)
        merkle_branch_hex_.push_back(util::to_hex(node));

    if (block_template.coinbase_script_sig_prefix.empty())
        throw std::invalid_argument("coinbase scriptSig prefix is empty");
    append(tag_, work_identifier);
    Bytes script_sig_prefix = std::move(block_template.coinbase_script_sig_prefix);
    if (!work_identifier.empty()) {
        // Keep changing extranonce and identifier bytes inert under sigop counting.
        const size_t data_size = extranonce_size_ + tag_.size();
        if (data_size > bitcoin::kMaxScriptSig)
            throw std::invalid_argument("coinbase data exceeds scriptSig budget");
        if (data_size > kMaximumDirectPushSize)
            script_sig_prefix.push_back(kOpPushData1);
        script_sig_prefix.push_back(static_cast<uint8_t>(data_size));
    }
    coinbase1_ = bitcoin::build_coinbase1(
        script_sig_prefix, extranonce_size_, tag_,
        block_template.coinbase_version.value_or(coinbase_version));
    coinbase1_hex_ = util::to_hex(coinbase1_);
    version_hex_ = std::format("{:08x}", version_);
    ntime_hex_ = std::format("{:08x}", curtime_);

    work_signature_ = prevhash_stratum_;
    work_signature_ += '|' + version_hex_;
    work_signature_ += '|' + nbits_hex_;
    work_signature_ += '|' + ntime_hex_;
    work_signature_ += '|' + coinbase1_hex_;
    // The per-job identifier must not defeat duplicate-template suppression.
    work_signature_ += '|' + util::to_hex(tag);
    work_signature_ += '|' + std::to_string(coinbase_value_);
    work_signature_ += '|' + std::to_string(coinbase_sequence_);
    work_signature_ += '|' + std::to_string(coinbase_lock_time_);
    if (coinbase_witness_)
        work_signature_ += '|' + util::to_hex(*coinbase_witness_);
    for (const auto& output : coinbase_required_outputs_) {
        work_signature_ += '|' + std::to_string(output.value);
        work_signature_ += ':' + util::to_hex(output.script);
    }
    for (const auto& branch : merkle_branch_hex_)
        work_signature_ += '|' + branch;
}

Bytes Job::build_coinbase2(ByteView payout_script) const {
    std::vector<bitcoin::CoinbaseOutput> outputs;
    if (donation_percent_ > 0.0 && !donation_script_.empty()) {
        const uint64_t donation_amount = static_cast<uint64_t>(
            static_cast<double>(coinbase_value_) * donation_percent_ / 100.0);
        outputs.push_back(
            {coinbase_value_ - donation_amount, Bytes(payout_script.begin(), payout_script.end())});
        outputs.push_back({donation_amount, donation_script_});
    } else {
        outputs.push_back({coinbase_value_, Bytes(payout_script.begin(), payout_script.end())});
    }
    return bitcoin::build_coinbase2(outputs, coinbase_required_outputs_, tag_, coinbase_sequence_,
                                    coinbase_lock_time_);
}

StandardWork Job::build_standard_work(ByteView payout_script, ByteView extranonce_prefix) const {
    if (extranonce_prefix.size() != extranonce_size_)
        throw std::invalid_argument("SV2 extranonce prefix does not fill the template extranonce");

    StandardWork work;
    const Bytes coinbase2 = build_coinbase2(payout_script);
    work.legacy_coinbase.reserve(coinbase1_.size() + extranonce_prefix.size() + coinbase2.size());
    append(work.legacy_coinbase, coinbase1_);
    append(work.legacy_coinbase, extranonce_prefix);
    append(work.legacy_coinbase, coinbase2);
    work.merkle_root =
        util::merkle_root_from_branch(util::sha256d(work.legacy_coinbase), merkle_branch_);
    return work;
}

ExtendedWork Job::build_extended_work(ByteView payout_script) const {
    return {coinbase1_, build_coinbase2(payout_script), merkle_branch_};
}

double Job::network_difficulty() const {
    return util::difficulty_from_target(network_target_);
}

bool Job::mines_on(const std::string& tip_display_hex) const {
    try {
        return util::reversed(util::from_hex(tip_display_hex)) == prevhash_internal_;
    } catch (const std::invalid_argument&) {
        return false; // malformed hex can't be our parent
    }
}

std::array<uint8_t, util::kHeaderSize> Job::build_header(const util::Hash256& merkle_root,
                                                         uint32_t ntime, uint32_t nonce,
                                                         uint32_t version) const {
    // Layout pinned in util/block_header.hpp. Fixed-size stack write: per submitted share, no heap.
    std::array<uint8_t, util::kHeaderSize> header;
    util::write_le32(header.data() + util::kVersionOffset, version);
    std::copy_n(prevhash_internal_.data(), 32, header.data() + util::kPrevhashOffset);
    std::copy_n(merkle_root.data(), 32, header.data() + util::kMerkleOffset);
    util::write_le32(header.data() + util::kTimeOffset, ntime);
    util::write_le32(header.data() + util::kBitsOffset, bits_);
    util::write_le32(header.data() + util::kNonceOffset, nonce);
    return header;
}

std::expected<ShareResult, ShareRejection> Job::validate_share(const ShareInput& input) const {
    // Cheap length gate before hex-decode (an oversized extranonce2 always rejects).
    if (input.extranonce2_hex.size() > extranonce2_size_ * 2) [[unlikely]]
        return rejected(ShareReject::InvalidExtranonce2Size);

    const auto extranonce2 = util::try_from_hex(input.extranonce2_hex);
    const auto ntime_opt = util::try_parse_hex_u32(input.ntime_hex);
    const auto nonce_opt = util::try_parse_hex_u32(input.nonce_hex);
    if (!extranonce2 || !ntime_opt || !nonce_opt) [[unlikely]]
        return rejected(ShareReject::MalformedField);
    const uint32_t ntime = *ntime_opt;
    const uint32_t nonce = *nonce_opt;

    if (extranonce2->size() != extranonce2_size_) [[unlikely]]
        return rejected(ShareReject::InvalidExtranonce2Size);

    const int64_t ntime_min = static_cast<int64_t>(curtime_);
    const int64_t ntime_max = input.now_unix + kNtimeSlack - kNtimeSubmitMargin;
    if (static_cast<int64_t>(ntime) < ntime_min || static_cast<int64_t>(ntime) > ntime_max) [[unlikely]]
        return rejected(ShareReject::NtimeOutOfRange);

    uint32_t version = version_;
    if (input.version_bits_hex) {
        const auto rolled_opt = util::try_parse_hex_u32(*input.version_bits_hex);
        if (!rolled_opt) [[unlikely]]
            return rejected(ShareReject::MalformedVersionBits);
        const uint32_t rolled = *rolled_opt;
        if (input.version_mask == 0) {
            if (rolled != 0) [[unlikely]]
                return rejected(ShareReject::VersionRollingNotNegotiated);
        } else if (rolled & ~input.version_mask) [[unlikely]] {
            return rejected(ShareReject::VersionBitsOutsideMask);
        } else {
            version = (version_ & ~input.version_mask) | (rolled & input.version_mask);
        }
    }

    Bytes coinbase;
    coinbase.reserve(coinbase1_.size() + input.extranonce1.size() + extranonce2->size() +
                     input.coinbase2.size());
    append(coinbase, coinbase1_);
    append(coinbase, input.extranonce1);
    append(coinbase, *extranonce2);
    append(coinbase, input.coinbase2);

    const util::Hash256 root =
        util::merkle_root_from_branch(util::sha256d(coinbase), merkle_branch_);
    return validate_header(std::move(coinbase), root, ntime, nonce, version, input.share_target);
}

std::expected<ShareResult, ShareRejection>
Job::validate_standard_share(const StandardShareInput& input) const {
    const int64_t ntime_min = static_cast<int64_t>(curtime_);
    const int64_t ntime_max = input.now_unix + kNtimeSlack - kNtimeSubmitMargin;
    if (static_cast<int64_t>(input.ntime) < ntime_min ||
        static_cast<int64_t>(input.ntime) > ntime_max) [[unlikely]]
        return rejected(ShareReject::NtimeOutOfRange);

    if ((input.version & ~input.version_mask) != (version_ & ~input.version_mask)) [[unlikely]]
        return rejected(ShareReject::VersionBitsOutsideMask);

    return validate_header(Bytes(input.legacy_coinbase.begin(), input.legacy_coinbase.end()),
                           input.merkle_root, input.ntime, input.nonce, input.version,
                           input.share_target);
}

std::expected<ShareResult, ShareRejection>
Job::validate_extended_share(const ExtendedWork& work, const ExtendedShareInput& input) const {
    if (input.extranonce.size() != input.extranonce_size ||
        input.extranonce_prefix.size() > extranonce_size_ ||
        input.extranonce_size != extranonce_size_ - input.extranonce_prefix.size()) [[unlikely]]
        return rejected(ShareReject::InvalidExtranonce2Size);

    Bytes coinbase;
    coinbase.reserve(work.coinbase_tx_prefix.size() + input.extranonce_prefix.size() +
                     input.extranonce.size() + work.coinbase_tx_suffix.size());
    append(coinbase, work.coinbase_tx_prefix);
    append(coinbase, input.extranonce_prefix);
    append(coinbase, input.extranonce);
    append(coinbase, work.coinbase_tx_suffix);

    StandardShareInput standard_input;
    standard_input.legacy_coinbase = coinbase;
    standard_input.merkle_root =
        util::merkle_root_from_branch(util::sha256d(coinbase), work.merkle_path);
    standard_input.ntime = input.ntime;
    standard_input.nonce = input.nonce;
    standard_input.version = input.version;
    standard_input.version_mask = input.version_mask;
    standard_input.share_target = input.share_target;
    standard_input.now_unix = input.now_unix;
    return validate_standard_share(standard_input);
}

std::expected<ShareResult, ShareRejection>
Job::validate_header(Bytes legacy_coinbase, const util::Hash256& merkle_root, uint32_t ntime,
                     uint32_t nonce, uint32_t version,
                     const util::uint256& share_target) const {
    const std::array<uint8_t, util::kHeaderSize> header =
        build_header(merkle_root, ntime, nonce, version);
    const util::Hash256 block_hash = util::sha256d(header);
    const util::uint256 hash_value = util::uint256::from_le_bytes(block_hash);

    const double difficulty = util::difficulty_from_target(hash_value);
    const bool is_block = util::meets_target(hash_value, network_target_);

    if (!is_block && !util::meets_target(hash_value, share_target))
        return std::unexpected(ShareRejection{ShareReject::AboveTarget, difficulty});

    ShareResult result;
    result.difficulty = difficulty;
    result.is_block = is_block;
    result.header = header;
    util::to_hex_reversed_into(result.block_hash_chars, block_hash);
    result.legacy_coinbase = std::move(legacy_coinbase);
    return result;
}

std::string Job::build_block_hex(ByteView legacy_coinbase, ByteView header) const {
    const Bytes coinbase =
        coinbase_witness_
            ? bitcoin::legacy_to_witness(legacy_coinbase, *coinbase_witness_)
            : Bytes(legacy_coinbase.begin(), legacy_coinbase.end());
    Bytes block;
    append(block, header);
    append(block, util::encode_varint(txn_count_ + 1));
    append(block, coinbase);
    append(block, txn_data_);
    return util::to_hex(block);
}

} // namespace erikslund::stratum

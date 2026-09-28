#include "bitcoin/work_source_rpc.hpp"

#include <cstdint>

#include <glaze/glaze.hpp>

#include "core/errors.hpp"

namespace erikslund::bitcoin {

namespace {
constexpr int64_t kRpcBlockNotFound = -5;
// How far below a branch tip the standing check walks to find the block. The block normally IS the
// tip: the pool builds on tips, and the node rarely learns further headers on an abandoned branch.
constexpr int64_t kMaxBranchWalk = 16;

std::string opt_str(glz::generic& obj, const char* key, const std::string& fallback) {
    if (obj.contains(key) && obj[key].is_string())
        return obj[key].get<std::string>();
    return fallback;
}
int64_t opt_int(glz::generic& obj, const char* key, int64_t fallback) {
    if (obj.contains(key) && obj[key].is_number())
        return static_cast<int64_t>(obj[key].get<double>());
    return fallback;
}
int64_t require_int(glz::generic& obj, const char* key) {
    if (!obj.contains(key) || !obj[key].is_number())
        throw RpcError(std::string("bitcoind reply missing numeric field: ") + key);
    return static_cast<int64_t>(obj[key].get<double>());
}
std::string require_str(glz::generic& obj, const char* key) {
    if (!obj.contains(key) || !obj[key].is_string())
        throw RpcError(std::string("bitcoind reply missing string field: ") + key);
    return obj[key].get<std::string>();
}
} // namespace

ChainInfo RpcWorkSource::detect_chain() {
    auto info = client_.getblockchaininfo();
    return ChainInfo{.chain = opt_str(info, "chain", "regtest"), .blocks = opt_int(info, "blocks", 0)};
}

HeaderFacts RpcWorkSource::fetch_header(const std::string& block_hash) {
    auto header = client_.getblockheader(block_hash);
    return HeaderFacts{
        .height = require_int(header, "height"),
        .confirmations = opt_int(header, "confirmations", -1),
        .bits_hex = require_str(header, "bits"),
        .mediantime = static_cast<uint32_t>(require_int(header, "mediantime")),
    };
}

BlockStanding RpcWorkSource::block_standing(const std::string& block_hash) {
    int64_t height = 0;
    try {
        auto header = client_.getblockheader(block_hash);
        if (opt_int(header, "confirmations", -1) >= 1)
            return BlockStanding::Active;
        height = require_int(header, "height");
    } catch (const RpcError& error) {
        if (error.code() == kRpcBlockNotFound)
            return BlockStanding::Pending; // the node has not even seen the header yet
        throw;
    }

    // Off the active chain: the status of the branch holding the block says whether the node
    // rejected it (invalid), validated it and moved elsewhere (valid-fork), or is still catching up.
    auto tips = client_.getchaintips();
    if (!tips.is_array())
        throw RpcError("getchaintips returned a non-array");
    for (auto& tip : tips.get_array()) {
        if (!tip.is_object())
            continue;
        const std::string status = opt_str(tip, "status", "");
        const int64_t tip_height = opt_int(tip, "height", -1);
        const int64_t branch_length = opt_int(tip, "branchlen", 0);
        // A branch covers the heights (tip_height - branch_length, tip_height].
        if (status.empty() || status == "active" || height > tip_height ||
            height <= tip_height - branch_length || tip_height - height > kMaxBranchWalk)
            continue;
        std::string ancestor = opt_str(tip, "hash", "");
        for (int64_t walk = tip_height; walk > height && !ancestor.empty(); --walk) {
            auto header = client_.getblockheader(ancestor);
            ancestor = opt_str(header, "previousblockhash", "");
        }
        if (ancestor != block_hash)
            continue;
        return status == "invalid" || status == "valid-fork" ? BlockStanding::Abandoned
                                                             : BlockStanding::Pending;
    }
    return BlockStanding::Unknown;
}

} // namespace erikslund::bitcoin

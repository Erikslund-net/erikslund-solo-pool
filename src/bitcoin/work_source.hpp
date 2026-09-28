#pragma once
// Work-template source used by Pool. IPC can replace template fetching; all other node operations
// remain on RPC.
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "bitcoin/block_template.hpp"

namespace erikslund::bitcoin {

// Startup handshake (RPC: getblockchaininfo). Feeds Pool::detect_network.
struct ChainInfo {
    std::string chain;
    int64_t blocks = 0;
};

struct HeaderFacts {
    int64_t height = 0;          // the header's OWN height; the core adds +1 for the next block
    int64_t confirmations = -1;  // == 1 proves this hash is the active tip now (fastblock gate)
    std::string bits_hex;        // the new tip's nBits, reused verbatim for the empty job
    uint32_t mediantime = 0;     // MTP -> the ntime floor (curtime = max(now, MTP + 1))
};

// How the serving node regards a block the pool is building on.
enum class BlockStanding {
    Unknown,   // the source cannot tell
    Active,    // in the node's active chain
    Pending,   // not active yet: unknown to the node or its branch is not fully validated
    Abandoned, // the node marked its branch invalid or reorganized onto another chain
};

class WorkSource {
public:
    virtual ~WorkSource() = default;

    // Startup handshake. May throw RpcConnectionError until bitcoind is reachable (main.cpp retries).
    virtual ChainInfo detect_chain() = 0;

    // Cheap tip probe -- the ~100-byte gate refresh_work uses before the heavy fetch. May throw.
    virtual std::string get_tip() = 0;

    // The heavy fetch. Returns the coinbase-buildable template BY VALUE; make_job consumes it
    // unchanged. May throw. Any failover / parse-stickiness lives entirely inside the backend.
    virtual BlockTemplate fetch_template() = 0;

    // Grounds the fastblock empty job. May throw.
    virtual HeaderFacts fetch_header(const std::string& block_hash) = 0;

    // Separates a node that abandoned the pool's current parent from one still catching up to it,
    // which decides whether a lower-height template may replace current work. May throw.
    virtual BlockStanding block_standing(const std::string& /*block_hash*/) {
        return BlockStanding::Unknown;
    }

    // Full-block submission stays on RPC even when templates come from IPC. This keeps live submits
    // and spool replay on one durable path and avoids coupling a share to mutable IPC template state.
    virtual std::optional<std::string> submit_block_hex(const std::string& block_hex) = 0;

    // Reverse failover (status_loop). No-op for a single backend.
    virtual void maybe_failback(const std::string& /*expected_tip*/) {}

    // Snapshot plumbing for the HTTP/Prometheus node view.
    virtual std::vector<std::string> endpoint_urls() const { return {}; }
    virtual std::size_t active_index() const { return 0; }

    // Cancel a blocking backend call during shutdown. RPC calls have their own deadline.
    virtual void interrupt() noexcept {}
};

} // namespace erikslund::bitcoin

#pragma once
// Synchronous bitcoind JSON-RPC over libcurl. One persistent easy handle PER THREAD, reused across
// calls for HTTP keep-alive + DNS caching (an easy handle is not shared between threads).
// Failover skips unreachable or temporarily unavailable nodes and sticks after a valid response.
#include <atomic>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <glaze/glaze.hpp>

#include "bitcoin/block_template.hpp"
#include "bitcoin/rpc_endpoint.hpp"

namespace erikslund::bitcoin {

struct MiningTip {
    std::string hash;
    int64_t height;
};

class RpcClient {
public:
    RpcClient(std::string url, const std::string& user, const std::string& password,
              long timeout_seconds = 30);
    explicit RpcClient(const std::vector<RpcEndpoint>& endpoints, long timeout_seconds = 30);

    glz::generic call(const std::string& method, const glz::generic& params = glz::generic{},
                      long timeout = 0);

    BlockTemplate getblocktemplate_parsed();
    // Send solved blocks to every node; acceptance or a valid duplicate from any node wins.
    std::optional<std::string> submitblock(const std::string& block_hex);
    glz::generic validateaddress(const std::string& address);
    glz::generic getblockchaininfo();
    // Cheap tip probe that gates the multi-MB getblocktemplate poll.
    std::string getbestblockhash();
    // Verbose header (height/bits/mediantime); grounds the fastblock empty job.
    glz::generic getblockheader(const std::string& block_hash);
    // Check readiness and read the tip from one endpoint; the caller handles fallback.
    MiningTip get_mining_tip();

    size_t endpoint_count() const { return endpoints_.size(); }

    std::vector<std::string> endpoint_urls() const;
    size_t active_index() const { return current_.load(); }

    void maybe_failback(const std::string& expected_tip);
    std::optional<BlockTemplate> try_fetch_failback_template();
    static constexpr double kFailbackProbeSeconds = 60.0;

    virtual ~RpcClient() = default;

protected:
    struct Resolved {
        std::string url;
        std::string auth_header;
    };
    virtual glz::generic call_one(const Resolved& endpoint, const std::string& payload,
                                  long timeout);
    virtual std::string post_one(const Resolved& endpoint, const std::string& payload, long timeout,
                                 long* http_status = nullptr);

private:
    std::string make_payload(const std::string& method,
                             const glz::generic& params = glz::generic{});
    glz::generic call_payload(const std::string& payload, long timeout);
    std::string make_getblocktemplate_payload();
    BlockTemplate fetch_template_from(size_t index, const std::string& payload,
                                      std::string& response_body);

    std::vector<Resolved> endpoints_;
    std::atomic<size_t> current_{0};
    long timeout_;
    long connect_timeout_;
    long poll_timeout_;
    std::atomic<int> next_id_{0};
    std::atomic<double> last_failback_probe_{-std::numeric_limits<double>::infinity()};
    mutable std::mutex failback_mutex_;
    std::optional<BlockTemplate> failback_template_;

    // Only work refresh uses this buffer; failback probes keep their own response.
    std::string gbt_body_;
};

} // namespace erikslund::bitcoin

#pragma once
// The RPC + ZMQ WorkSource: a thin adapter over the existing multi-endpoint RpcClient. ZMQ is not
// wrapped here -- it stays an independent transport calling Pool::on_zmq_block; this backend only
// serves that path via fetch_header(). All failover / parse-stickiness lives inside RpcClient,
// below this adapter, so the pool core never sees an endpoint.
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "bitcoin/rpc_client.hpp"
#include "bitcoin/work_source.hpp"

namespace erikslund::bitcoin {

class RpcWorkSource final : public WorkSource {
public:
    explicit RpcWorkSource(RpcClient& client) : client_(client) {}

    ChainInfo detect_chain() override;
    std::string get_tip() override { return client_.getbestblockhash(); }
    BlockTemplate fetch_template() override { return client_.getblocktemplate_parsed(); }
    MiningTip get_mining_tip() { return client_.get_mining_tip(); }
    HeaderFacts fetch_header(const std::string& block_hash) override;
    std::optional<std::string> submit_block_hex(const std::string& block_hex) override {
        return client_.submitblock(block_hex);
    }
    void maybe_failback(const std::string& expected_tip) override {
        client_.maybe_failback(expected_tip);
    }
    std::optional<BlockTemplate> try_fetch_failback_template() {
        return client_.try_fetch_failback_template();
    }
    std::vector<std::string> endpoint_urls() const override { return client_.endpoint_urls(); }
    std::size_t active_index() const override { return client_.active_index(); }

private:
    RpcClient& client_;
};

} // namespace erikslund::bitcoin

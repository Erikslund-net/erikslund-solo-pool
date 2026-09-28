#pragma once
// IPC template source with an authoritative RPC side channel during reconnects.
#include <atomic>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "bitcoin/mining_ipc_client.hpp"
#include "bitcoin/work_source_rpc.hpp"

namespace erikslund::bitcoin {

class IpcWorkSource final : public WorkSource {
public:
    IpcWorkSource(MiningIpcClient& client, RpcWorkSource& rpc, std::string endpoint_label)
        : client_(client), rpc_(rpc), endpoint_label_(std::move(endpoint_label)) {}

    IpcWorkSource(const IpcWorkSource&) = delete;
    IpcWorkSource& operator=(const IpcWorkSource&) = delete;

    ChainInfo detect_chain() override { return rpc_.detect_chain(); }
    std::string get_tip() override { return rpc_.get_tip(); }
    BlockTemplate fetch_template() override;
    HeaderFacts fetch_header(const std::string& block_hash) override {
        return rpc_.fetch_header(block_hash);
    }
    BlockStanding block_standing(const std::string& block_hash) override {
        return rpc_.block_standing(block_hash);
    }
    std::optional<std::string> submit_block_hex(const std::string& block_hex) override {
        return rpc_.submit_block_hex(block_hex);
    }
    void maybe_failback(const std::string& expected_tip) override {
        rpc_.maybe_failback(expected_tip);
    }
    std::vector<std::string> endpoint_urls() const override;
    std::size_t active_index() const override;
    void interrupt() noexcept override {
        if (stopping_.exchange(true, std::memory_order_acq_rel))
            return;
        ipc_active_.store(false, std::memory_order_relaxed);
        client_.interrupt();
    }

private:
    BlockTemplate fetch_rpc_template();

    MiningIpcClient& client_;
    RpcWorkSource& rpc_;
    std::string endpoint_label_;
    std::atomic<bool> ipc_active_{false};
    std::atomic<bool> stopping_{false};
    bool failure_reported_ = false;
};

} // namespace erikslund::bitcoin

#include "bitcoin/work_source_ipc.hpp"

#include <cstdint>
#include <exception>
#include <utility>

#include "core/errors.hpp"
#include "core/logging.hpp"

namespace erikslund::bitcoin {

BlockTemplate IpcWorkSource::fetch_template() {
    if (stopping_.load(std::memory_order_acquire))
        throw RpcConnectionError("IPC work source is stopping");
    if (auto failback_template = rpc_.try_fetch_failback_template()) {
        ipc_active_.store(false, std::memory_order_relaxed);
        return std::move(*failback_template);
    }
    if (!client_.available())
        return fetch_rpc_template();
    try {
        auto block_template = client_.create_block();
        const MiningTip tip = rpc_.get_mining_tip();
        if (stopping_.load(std::memory_order_acquire))
            throw RpcConnectionError("IPC work source is stopping");
        if (block_template.previousblockhash != tip.hash) {
            log::debug("IPC template parent {} is not the RPC tip {}; using RPC for this cycle",
                       block_template.previousblockhash, tip.hash);
        } else {
            if (block_template.height <= 0 || block_template.height - 1 != tip.height)
                throw RpcError("IPC template height does not follow the RPC tip height");
            failure_reported_ = false;
            if (!ipc_active_.exchange(true, std::memory_order_relaxed))
                log::info("IPC work source active");
            return block_template;
        }
    } catch (const std::exception& e) {
        ipc_active_.store(false, std::memory_order_relaxed);
        if (stopping_.load(std::memory_order_acquire))
            throw;
        if (!std::exchange(failure_reported_, true))
            log::warning("IPC work unavailable ({}); using RPC for work", e.what());
    }
    return fetch_rpc_template();
}

BlockTemplate IpcWorkSource::fetch_rpc_template() {
    ipc_active_.store(false, std::memory_order_relaxed);
    if (stopping_.load(std::memory_order_acquire))
        throw RpcConnectionError("IPC work source is stopping");
    return rpc_.fetch_template();
}

std::vector<std::string> IpcWorkSource::endpoint_urls() const {
    std::vector<std::string> endpoints{endpoint_label_};
    std::vector<std::string> rpc_endpoints = rpc_.endpoint_urls();
    endpoints.insert(endpoints.end(), rpc_endpoints.begin(), rpc_endpoints.end());
    return endpoints;
}

std::size_t IpcWorkSource::active_index() const {
    return ipc_active_.load(std::memory_order_relaxed) && client_.available()
               ? 0
               : rpc_.active_index() + 1;
}

} // namespace erikslund::bitcoin

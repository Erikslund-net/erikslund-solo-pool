#include "core/resource_limits.hpp"

#include <algorithm>
#include <cerrno>
#include <format>
#include <limits>
#include <string>
#include <system_error>

#include <sys/resource.h>

#include "api/http_server.hpp"
#include "core/config.hpp"
#include "core/errors.hpp"
#include "core/logging.hpp"

namespace erikslund::core {
namespace {

constexpr uint64_t kStandardFiles = 3;
constexpr uint64_t kFilesPerReactor = 2; // epoll and eventfd
constexpr uint64_t kApiListeners = 1;
// Startup, work refresh, ZMQ, recovery, and status/failback retain separate curl caches.
constexpr uint64_t kRpcCallers = 5;
// Immediate submission and recovery can each fan out to every configured node.
constexpr uint64_t kSubmitCallers = 2;
// Allow cached/connecting sockets plus curl and DNS resolver wakeup descriptors.
constexpr uint64_t kFilesPerRpcEndpoint = 8;
// Each mining reactor may spool a solved block while the other reactors keep mining.
constexpr uint64_t kSpoolFilesPerReactor = 2;
constexpr uint64_t kIpcFiles = 8; // UNIX socket, KJ event loop, and cross-thread wakeups
constexpr uint64_t kZmqFiles = 16; // socket, context mailboxes, and I/O/reaper pollers
// Concurrent stats/config/credential I/O, directory walks, and transient accepts.
constexpr uint64_t kFileHeadroom = 16;
constexpr uint64_t kUnlimitedFiles = std::numeric_limits<uint64_t>::max();

} // namespace

FileBudget file_budget(const Config& config, unsigned workers, bool file_log,
                        uint64_t soft_limit) {
    if (config.max_clients < 0 || workers == 0)
        throw ConfigError("File budget requires nonnegative max_clients and resolved workers");

    const uint64_t listeners = (config.bind_ports.empty() ? 1 : config.bind_ports.size()) +
                               config.sv2_ports.size() + config.sv2_plaintext_ports.size();
    const uint64_t endpoints = 1 + config.rpc_failover.size();
    const uint64_t reserved =
        kStandardFiles + kFileHeadroom + listeners +
        workers * (kFilesPerReactor + kSpoolFilesPerReactor) +
        api::kMaxConnections + kApiListeners + api::kWorkerThreads * kFilesPerReactor +
        endpoints * (kRpcCallers + kSubmitCallers) * kFilesPerRpcEndpoint +
        (config.work_source == "ipc" ? kIpcFiles : 0) +
        (!config.zmq_block_endpoint.empty() ? kZmqFiles : 0) + (file_log ? 1 : 0);
    if (soft_limit < reserved || (soft_limit == reserved && config.max_clients > 0))
        throw ConfigError(std::format(
            "Open file limit {} cannot cover {} internal descriptors and mining clients; "
            "raise ulimit -n / LimitNOFILE", soft_limit, reserved));

    return {reserved, static_cast<int>(std::min<uint64_t>(
                          static_cast<uint64_t>(config.max_clients), soft_limit - reserved))};
}

void apply_file_budget(Config& config, unsigned workers, bool file_log) {
    const auto requested = file_budget(config, workers, file_log, kUnlimitedFiles);
    const uint64_t needed = requested.reserved + static_cast<uint64_t>(config.max_clients);
    rlimit nofile{};
    if (::getrlimit(RLIMIT_NOFILE, &nofile) != 0)
        throw std::system_error(errno, std::generic_category(), "getrlimit(RLIMIT_NOFILE)");
    if (nofile.rlim_cur != RLIM_INFINITY && nofile.rlim_cur < needed) {
        rlimit raised = nofile;
        raised.rlim_cur = static_cast<rlim_t>(std::min<uint64_t>(needed, nofile.rlim_max));
        if (raised.rlim_cur > nofile.rlim_cur && ::setrlimit(RLIMIT_NOFILE, &raised) != 0)
            log::warning("Cannot raise the open file limit: {}",
                         std::generic_category().message(errno));
        if (::getrlimit(RLIMIT_NOFILE, &nofile) != 0)
            throw std::system_error(errno, std::generic_category(), "getrlimit(RLIMIT_NOFILE)");
    }
    const uint64_t soft_limit = nofile.rlim_cur == RLIM_INFINITY
                                   ? kUnlimitedFiles : static_cast<uint64_t>(nofile.rlim_cur);
    const auto budget = file_budget(config, workers, file_log, soft_limit);
    if (budget.max_clients < config.max_clients)
        log::warning("Lowering max_clients from {} to {} to reserve {} internal descriptors; "
                     "raise ulimit -n / LimitNOFILE to allow more",
                     config.max_clients, budget.max_clients, budget.reserved);
    config.max_clients = budget.max_clients;
    log::info("FD budget: {} miners, {} internal descriptors, open file limit {}",
              config.max_clients, budget.reserved,
              soft_limit == kUnlimitedFiles ? std::string("unlimited") : std::to_string(soft_limit));
}

} // namespace erikslund::core

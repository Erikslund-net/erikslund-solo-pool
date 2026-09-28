// Entry point: load config, connect to bitcoind, start the server, run until signal.
#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <exception>
#include <optional>
#include <stop_token>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "api/http_server.hpp"
#include "bitcoin/capnp_mining_client.hpp"
#include "bitcoin/rpc_client.hpp"
#include "bitcoin/work_source_ipc.hpp"
#include "bitcoin/work_source_rpc.hpp"
#include "core/config.hpp"
#include "core/crash.hpp"
#include "core/errors.hpp"
#include "core/logging.hpp"
#include "core/resource_limits.hpp"
#include "core/version.hpp"
#include "mining/work_identity.hpp"
#include "net/server.hpp"
#include "net/zmq_subscriber.hpp"
#include "pool/pool.hpp"
#include "util/sha256.hpp"
#include "util/url.hpp"

#ifdef HAVE_MIMALLOC
#include <mimalloc.h>
#endif

namespace {
std::atomic<bool> g_shutdown{false};
std::atomic<bool> g_reload_requested{false};

extern "C" void handle_signal(int signum) {
    if (signum == SIGHUP)
        g_reload_requested.store(true, std::memory_order_relaxed);
    else
        g_shutdown.store(true, std::memory_order_relaxed);
}

void apply_api_overrides(erikslund::Config& config,
                         const std::optional<std::string>& host,
                         const std::optional<uint16_t>& port) {
    if (host)
        config.api_host = *host;
    if (port)
        config.api_port = *port;
}

std::string join_names(const std::vector<std::string>& names) {
    std::string joined;
    for (const std::string& name : names) {
        if (!joined.empty())
            joined += ", ";
        joined += name;
    }
    return joined;
}
} // namespace

int main(int argc, char** argv) {
    using namespace erikslund;

    core::install_crash_handlers(); // log a backtrace on SIGSEGV/abort/uncaught exception

    std::string config_path;
    std::string log_file;
    std::optional<std::string> api_host_override;
    std::optional<uint16_t> api_port_override;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc)
            config_path = argv[++i];
        else if (arg == "--api-host" && i + 1 < argc)
            api_host_override = argv[++i];
        else if (arg == "--api-port" && i + 1 < argc) {
            const std::string value = argv[++i];
            unsigned parsed = 0;
            const auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), parsed);
            if (ec != std::errc{} || ptr != value.data() + value.size() || parsed == 0 ||
                parsed > 65535) {
                log::error("Invalid --api-port '{}' (expected 1-65535)", value);
                return 1;
            }
            api_port_override = static_cast<uint16_t>(parsed);
        }
        else if (arg == "--log-file" && i + 1 < argc)
            log_file = argv[++i];
        else if (arg == "--debug")
            log::set_level(log::Level::Debug);
        else if (arg == "--quiet")
            log::set_level(log::Level::Warning);
    }

    if (!log_file.empty() && !log::set_log_file(log_file))
        log::warning("Cannot open log file '{}'; logging to stderr only", log_file);

    Config config;
    try {
        if (!config_path.empty())
            config = Config::from_file(config_path);
    } catch (const std::exception& e) {
        log::error("Config error: {}", e.what());
        return 1;
    }
    apply_api_overrides(config, api_host_override, api_port_override);

    log::info("erikslund-solo-pool v{} starting -- stratum {}:{}, bitcoind {}", kVersion,
                config.bind_host, config.bind_port, util::redact_url(config.rpc_url));
    const unsigned worker_count = net::resolve_worker_count(config.worker_threads);
    try {
        core::apply_file_budget(config, worker_count, !log_file.empty());
    } catch (const std::exception& error) {
        log::error("Cannot reserve file descriptors: {}", error.what());
        return 1;
    }
#ifdef HAVE_MIMALLOC
    const int mimalloc_version = mi_version();
    const bool mi_v3 = mimalloc_version >= 10000;
    const int mi_major = mi_v3 ? mimalloc_version / 10000 : mimalloc_version / 100;
    const int mi_minor = mi_v3 ? (mimalloc_version / 100) % 100 : (mimalloc_version / 10) % 10;
    const int mi_patch = mi_v3 ? mimalloc_version % 100 : mimalloc_version % 10;
    log::info("allocator: mimalloc {}.{}.{}", mi_major, mi_minor, mi_patch);
#endif
    log::info("sha256 backend: {}", util::sha256_init());

    bitcoin::RpcClient rpc(config.rpc_endpoints());
    if (!config.rpc_failover.empty())
        log::info("Bitcoind failover: {} endpoint(s) configured", config.rpc_endpoints().size());
    bitcoin::RpcWorkSource rpc_source(rpc);
    bitcoin::WorkSource* source = &rpc_source;
    std::optional<bitcoin::CapnpMiningClient> ipc_client;
    std::optional<bitcoin::IpcWorkSource> ipc_source;
    if (config.work_source == "ipc") {
        try {
            ipc_client.emplace(config.ipc_socket_path);
            ipc_source.emplace(*ipc_client, rpc_source, "ipc://" + config.ipc_socket_path);
            source = &*ipc_source;
            log::info("Work source: IPC at {} with reconnecting RPC fallback",
                      config.ipc_socket_path);
        } catch (const std::exception& e) {
            log::warning("Could not start IPC connection loop ({}); using RPC for work", e.what());
        }
    }
    uint64_t work_generation;
    try {
        work_generation = mining::reserve_work_generation(config.stats_directory);
        log::info("Reserved mining work generation {}", work_generation);
    } catch (const std::exception& error) {
        log::error("Cannot reserve mining work generation in {}: {}",
                   config.stats_directory, error.what());
        return 1;
    }
    Pool pool(config, *source, work_generation);

    // Install handlers before waiting on bitcoind so Ctrl-C / SIGTERM can interrupt the wait.
    // SIGPIPE ignored so a broken socket write never kills the process.
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    std::signal(SIGHUP, handle_signal);
    std::signal(SIGPIPE, SIG_IGN);

    // Retry rather than exit on first failure: bitcoind may still be warming up or its socket not
    // yet open. detect_network sets the network used for local address validation, so we can't
    // serve until it succeeds -- but we stay up and keep probing.
    bool network_detected = false;
    for (int attempt = 0; !network_detected && !g_shutdown.load(); ++attempt) {
        try {
            pool.detect_network();
            network_detected = true;
        } catch (const ConfigError& e) {
            log::error("Config error: {}", e.what());
            return 1;
        } catch (const std::exception& e) {
            if (attempt == 0)
                log::warning("Waiting for bitcoind at {}: {} (will keep retrying)",
                             util::redact_url(config.rpc_url), e.what());
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    if (!network_detected)
        return 0; // shutdown requested while waiting for bitcoind

    pool.recover_stats();           // resume cumulative stats from a prior pool.status
    pool.recover_user_stats();      // resume per-worker stats (hashrates decayed by file age)
    pool.resubmit_spooled_blocks(); // re-submit any block a previous run couldn't confirm

    Config server_config = config;
    server_config.worker_threads = static_cast<int>(worker_count);
    net::Server server(pool, server_config);
    try {
        server.start();
    } catch (const std::exception& e) {
        log::error("Cannot start stratum server: {}", e.what());
        return 1;
    }
    pool.set_connector_ready(true);

    // HTTP status / metrics API -- non-fatal if its port is unavailable.
    api::HttpServer api_server(pool, config.api_host, config.api_port);
    bool api_up = false;
    try {
        api_server.start();
        api_up = true;
    } catch (const std::exception& e) {
        log::warning("HTTP API disabled: {}", e.what());
    }

    std::stop_source stop;
    const std::stop_callback interrupt_work(stop.get_token(), [source] { source->interrupt(); });
    // The signal handler only sets flags; parsing and applying configuration happens here.
    std::jthread watcher([&stop, &pool, &server, config_path, api_host_override,
                          api_port_override, worker_count, file_log = !log_file.empty(),
                          active_config = config]() mutable {
        while (!g_shutdown.load(std::memory_order_relaxed) && !stop.stop_requested()) {
            if (g_reload_requested.exchange(false, std::memory_order_relaxed)) {
                if (config_path.empty()) {
                    pool.note_config_reload_rejected();
                    log::warning("Config reload ignored: the pool was started without --config");
                } else {
                    try {
                        Config replacement = Config::from_file(config_path);
                        apply_api_overrides(replacement, api_host_override, api_port_override);
                        const auto restart_required =
                            active_config.restart_required_changes(replacement);
                        if (!restart_required.empty()) {
                            pool.note_config_reload_rejected();
                            log::warning("Config reload rejected; restart required for: {}",
                                         join_names(restart_required));
                        } else {
                            core::apply_file_budget(replacement, worker_count, file_log);
                            const RuntimeConfig runtime_config = replacement.runtime_config();
                            pool.reload_config(runtime_config);
                            server.reload_config(runtime_config);
                            active_config = std::move(replacement);
                            log::info("Configuration reloaded from {}", config_path);
                        }
                    } catch (const std::exception& error) {
                        pool.note_config_reload_rejected();
                        log::warning("Config reload failed; keeping current settings: {}",
                                     error.what());
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        stop.request_stop();
    });
    // Each thread guards its body: a throw escaping a jthread calls std::terminate().
    std::jthread worker([&pool, &stop] {
        try {
            pool.refresh_work(stop.get_token());
        } catch (const std::exception& e) {
            log::error("work thread crashed: {}", e.what());
        }
    });
    std::jthread vardiff_thread([&pool, &stop] {
        try {
            pool.vardiff_loop(stop.get_token());
        } catch (const std::exception& e) {
            log::error("vardiff thread crashed: {}", e.what());
        }
    });
    std::jthread status_thread([&pool, &stop] {
        try {
            pool.status_loop(stop.get_token());
        } catch (const std::exception& e) {
            log::error("status thread crashed: {}", e.what());
        }
    });
    std::jthread api_thread;
    if (api_up)
        api_thread = std::jthread([&api_server, &stop] {
            try {
                api_server.run(stop.get_token());
            } catch (const std::exception& e) {
                log::error("api thread crashed: {}", e.what());
            }
        });
    std::jthread zmq_thread;
    if (!config.zmq_block_endpoint.empty())
        zmq_thread = std::jthread([&pool, &config, &stop] {
            try {
                net::ZmqSubscriber subscriber(pool, config.zmq_block_endpoint);
                subscriber.run(stop.get_token());
            } catch (const std::exception& e) {
                log::error("zmq thread crashed: {}", e.what());
            }
        });

    server.run(stop.get_token());
    stop.request_stop();
    watcher.join();
    worker.join();
    vardiff_thread.join();
    status_thread.join();
    if (api_thread.joinable())
        api_thread.join();
    if (zmq_thread.joinable())
        zmq_thread.join();
    pool.shutdown();

    log::info("Shutdown requested -- {} shares accepted, {} blocks found", pool.accepted_shares(),
              pool.blocks_found());
    return 0;
}

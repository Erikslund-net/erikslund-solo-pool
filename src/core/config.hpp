#pragma once
// Pool configuration and validation.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "bitcoin/rpc_endpoint.hpp"
#include "util/bytes.hpp"

namespace erikslund {

struct RuntimeConfig {
    double initial_difficulty;
    double minimum_difficulty;
    double maximum_difficulty;
    bool variable_difficulty;
    double vardiff_target_shares_per_minute;
    int vardiff_retarget_seconds;
    double work_rebroadcast_seconds;
    double poll_interval;
    double status_interval_seconds;
    int user_stats_retention_days;
    bool fast_block_notify;
    int max_clients;
    int max_workers_per_address;
    int drop_idle_seconds;
    int auth_timeout_seconds;
    int max_protocol_errors;
};

struct Config {
    // bitcoind JSON-RPC (primary endpoint).
    std::string rpc_url = "http://127.0.0.1:18443";
    std::string rpc_user = "erikslund";
    std::string rpc_password = "erikslundpass";
    // Additional bitcoind endpoints tried in order if the primary is unreachable.
    std::vector<bitcoin::RpcEndpoint> rpc_failover;

    // Stratum listener.
    std::string bind_host = "0.0.0.0";
    uint16_t bind_port = 3333;
    // Additional normal stratum ports to bind; empty = just bind_port.
    std::vector<uint16_t> bind_ports;
    // Optional SV2 compatibility listeners secured by Noise. Empty disables them.
    std::string sv2_host = "0.0.0.0";
    std::vector<uint16_t> sv2_ports;
    // Raw responder credential files: 32-byte static secret, 32-byte x-only authority public key,
    // and 74-byte pre-signed certificate. The authority private key never enters the pool.
    std::string sv2_static_secret_key_file;
    std::string sv2_authority_public_key_file;
    std::string sv2_certificate_file;
    // Development-only plaintext SV2 listeners. Empty disables them; only loopback is accepted.
    std::string sv2_plaintext_host = "127.0.0.1";
    std::vector<uint16_t> sv2_plaintext_ports;
    // Trusted upstreams (exact IP or IPv4 CIDR) allowed to send a PROXY-protocol header, attributed
    // to the real client IP. Empty = off. Non-trusted sources are treated as direct (no spoofing).
    std::vector<std::string> proxy_protocol_from;

    // HTTP status / metrics API listener (Prometheus at /metrics).
    std::string api_host = "127.0.0.1";
    uint16_t api_port = 7777;

    // Difficulty.
    double initial_difficulty = 1.0;
    double minimum_difficulty = 0.001;
    double maximum_difficulty = 0.0; // operator upper clamp (0 = network ceiling only)

    // Per-client retargeting toward a share rate.
    bool variable_difficulty = true;
    double vardiff_target_shares_per_minute = 12.0;
    int vardiff_retarget_seconds = 60;

    // BIP320 version-rolling bits a client may roll (negotiation cap).
    uint32_t version_rolling_mask = 0x1fffe000;

    // Extranonce sizes (bytes).
    size_t extranonce1_size = 4;
    size_t extranonce2_size = 8;
    Bytes extranonce1_prefix;

    // Coinbase.
    std::string coinbase_signature = "/erikslund-pool/";
    uint32_t coinbase_version = 1;

    // Second coinbase output paying donation_percent to donation_address. 0 = off.
    double donation_percent = 0.0;
    std::string donation_address;

    // Re-poll getblocktemplate this often even without a new block (roll ntime / new txs).
    double work_rebroadcast_seconds = 30.0;
    double poll_interval = 1.0;

    // On-disk stats.
    std::string stats_directory = "stats";
    double status_interval_seconds = 30.0;
    // Prune a users/<address> file once the address has been inactive (disconnected; the file
    // no longer rewritten) this many days. Connected miners are never pruned. 0 = keep forever.
    int user_stats_retention_days = 90;

    // Optional bitcoind ZMQ hashblock endpoint, e.g. tcp://127.0.0.1:28332.
    std::string zmq_block_endpoint;
    // On a ZMQ block, broadcast empty work before the slow getblocktemplate.
    bool fast_block_notify = true;

    std::string work_source = "rpc";
    std::string ipc_socket_path = "/tmp/btc-mining.sock";

    // Safety limits.
    int max_clients = 1024;
    // Max worker rows itemized in one address's stats file. Connections beyond this still mine and
    // count toward address totals; their per-worker stats fold into one bucket under the bare
    // address. Not a connection cap. 0 = unlimited.
    int max_workers_per_address = 256;
    size_t max_line_bytes = 16384; // maximum SV1 line or SV2 frame payload
    int drop_idle_seconds = 3600; // drop a client idle this long (0 = never)
    int auth_timeout_seconds = 30; // drop a client that never authorizes (0 = never)
    int max_protocol_errors = 100; // drop after this many bad requests since the last accepted share (0 = never)

    // Connection-serving epoll reactor threads. 0 = auto (one per core, clamped).
    int worker_threads = 0;

    // Primary followed by failover endpoints, in order.
    std::vector<bitcoin::RpcEndpoint> rpc_endpoints() const {
        std::vector<bitcoin::RpcEndpoint> all{{rpc_url, rpc_user, rpc_password}};
        all.insert(all.end(), rpc_failover.begin(), rpc_failover.end());
        return all;
    }

    std::vector<uint16_t> stratum_ports() const {
        return bind_ports.empty() ? std::vector<uint16_t>{bind_port} : bind_ports;
    }

    RuntimeConfig runtime_config() const;
    std::vector<std::string> restart_required_changes(const Config& replacement) const;

    static Config from_string(const std::string& text);
    static Config from_file(const std::string& path);
};

} // namespace erikslund

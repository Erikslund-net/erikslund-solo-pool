#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "core/config.hpp"
#include "core/errors.hpp"
#include "util/hex.hpp"

using namespace erikslund;

TEST_CASE("defaults are the regtest harness values") {
    const Config config = Config::from_string("{}");
    CHECK(config.rpc_url == "http://127.0.0.1:18443");
    CHECK(config.bind_port == 3333);
    CHECK(config.extranonce2_size == 8);
    CHECK(config.coinbase_version == 1);
}

TEST_CASE("known keys override, others keep defaults") {
    const Config config = Config::from_string(R"({
        "bitcoin_nodes": [{"address": "http://node:8332", "username": "u", "password": "p"}],
        "stratum_listen": ["0.0.0.0:4444"],
        "initial_difficulty": 1024,
        "coinbase_signature": "/test/"
    })");
    CHECK(config.rpc_url == "http://node:8332");
    CHECK(config.rpc_user == "u");
    CHECK(config.bind_port == 4444);
    CHECK(config.initial_difficulty == doctest::Approx(1024.0));
    CHECK(config.coinbase_signature == "/test/");
    CHECK(config.api_port == 7777); // untouched default
}

TEST_CASE("the pool config schema parses into the typed config") {
    const Config c = Config::from_string(R"({
        "bitcoin_nodes": [
            {"address": "bitcoind:8332", "username": "u", "password": "p", "notify": true},
            {"address": "backup:8332", "username": "u2", "password": "p2"}
        ],
        "stratum_listen": ["0.0.0.0:3333", "0.0.0.0:4001"],
        "coinbase_signature": "/erikslund/",
        "initial_difficulty": 10000,
        "minimum_difficulty": 1,
        "maximum_difficulty": 1000000,
        "extranonce1_size": 4,
        "extranonce2_size": 8,
        "api_listen": ["127.0.0.1:7777"],
        "zmq_block_endpoint": "tcp://bitcoind:28332",
        "block_poll_milliseconds": 250,
        "work_rebroadcast_seconds": 20,
        "max_clients": 50,
        "drop_idle_seconds": 900,
        "auth_timeout_seconds": 45,
        "max_protocol_errors": 7,
        "worker_threads": 6,
        "version_rolling_mask": "1fffe000"
    })");
    CHECK(c.rpc_url == "bitcoind:8332"); // scheme added later by RpcClient
    CHECK(c.rpc_user == "u");
    CHECK(c.rpc_password == "p");
    REQUIRE(c.rpc_failover.size() == 1);
    CHECK(c.rpc_failover[0].url == "backup:8332");
    CHECK(c.rpc_endpoints().size() == 2);
    CHECK(c.stratum_ports() == std::vector<uint16_t>{3333, 4001});
    CHECK(c.bind_host == "0.0.0.0");
    CHECK(c.coinbase_signature == "/erikslund/");
    CHECK(c.initial_difficulty == doctest::Approx(10000.0));
    CHECK(c.minimum_difficulty == doctest::Approx(1.0));
    CHECK(c.maximum_difficulty == doctest::Approx(1000000.0));
    CHECK(c.extranonce1_size == 4);
    CHECK(c.extranonce2_size == 8);
    CHECK(c.api_host == "127.0.0.1");
    CHECK(c.api_port == 7777);
    CHECK(c.zmq_block_endpoint == "tcp://bitcoind:28332");
    CHECK(c.poll_interval == doctest::Approx(0.25)); // block_poll_milliseconds -> seconds
    CHECK(c.work_rebroadcast_seconds == doctest::Approx(20.0));
    CHECK(c.max_clients == 50);
    CHECK(c.drop_idle_seconds == 900);
    CHECK(c.auth_timeout_seconds == 45);
    CHECK(c.max_protocol_errors == 7);
    CHECK(c.worker_threads == 6);
    CHECK(c.version_rolling_mask == 0x1fffe000u);
}

TEST_CASE("a single stratum_listen string is accepted") {
    const Config config = Config::from_string(R"({"stratum_listen": "0.0.0.0:3333"})");
    CHECK(config.bind_host == "0.0.0.0");
    CHECK(config.stratum_ports() == std::vector<uint16_t>{3333});
}

TEST_CASE("SV2 plaintext listeners are disabled by default and default to loopback") {
    CHECK(Config::from_string("{}").sv2_plaintext_ports.empty());

    const Config config = Config::from_string(
        R"({"sv2_plaintext_listen": [":3334", ":3335"]})");
    CHECK(config.sv2_plaintext_host == "127.0.0.1");
    CHECK(config.sv2_plaintext_ports == std::vector<uint16_t>{3334, 3335});
}

TEST_CASE("SV2 plaintext listeners reject mixed hosts") {
    CHECK_THROWS_AS(
        Config::from_string(
            R"({"sv2_plaintext_listen": ["127.0.0.1:3334", "0.0.0.0:3335"]})"),
        ConfigError);
    CHECK_THROWS_AS(
        Config::from_string(R"({"sv2_plaintext_listen": "0.0.0.0:3334"})"),
        ConfigError);
}

TEST_CASE("SV2 Noise listeners require a complete responder credential set") {
    CHECK(Config::from_string("{}").sv2_ports.empty());
    CHECK_THROWS_AS(
        Config::from_string(R"({"sv2_listen": ":3334"})"),
        ConfigError);
    CHECK_THROWS_AS(
        Config::from_string(
            R"({"sv2_static_secret_key_file": "static.key"})"),
        ConfigError);

    const Config config = Config::from_string(R"({
        "sv2_listen": [":3334", ":3335"],
        "sv2_static_secret_key_file": "/run/secrets/sv2-static",
        "sv2_authority_public_key_file": "/run/secrets/sv2-authority",
        "sv2_certificate_file": "/run/secrets/sv2-certificate"
    })");
    CHECK(config.sv2_host == "0.0.0.0");
    CHECK(config.sv2_ports == std::vector<uint16_t>{3334, 3335});
    CHECK(config.sv2_static_secret_key_file == "/run/secrets/sv2-static");
}

TEST_CASE("SV2 Noise listeners reject mixed hosts") {
    CHECK_THROWS_AS(
        Config::from_string(R"({
            "sv2_listen": ["127.0.0.1:3334", "0.0.0.0:3335"],
            "sv2_static_secret_key_file": "static.key",
            "sv2_authority_public_key_file": "authority.pub",
            "sv2_certificate_file": "certificate.bin"
        })"),
        ConfigError);
}

TEST_CASE("authenticated and plaintext SV2 listeners must use distinct ports") {
    const std::string credentials = R"(
        "sv2_static_secret_key_file": "static.key",
        "sv2_authority_public_key_file": "authority.pub",
        "sv2_certificate_file": "certificate.bin"
    )";

    CHECK_THROWS_AS(
        Config::from_string(
            R"({"sv2_listen": "127.0.0.1:3334",
                "sv2_plaintext_listen": "127.0.0.1:3334",)" +
            credentials + "}"),
        ConfigError);
    CHECK_THROWS_AS(
        Config::from_string(
            R"({"sv2_listen": ":3334",
                "sv2_plaintext_listen": ":3334",)" +
            credentials + "}"),
        ConfigError);

    CHECK_THROWS_AS(
        Config::from_string(
            R"({"sv2_listen": "192.0.2.1:3334",
                "sv2_plaintext_listen": "127.0.0.1:3334",)" +
            credentials + "}"),
        ConfigError);
    CHECK_NOTHROW(Config::from_string(
        R"({"sv2_listen": "127.0.0.1:3334",
            "sv2_plaintext_listen": "127.0.0.1:13334",)" +
        credentials + "}"));
}

TEST_CASE("proxy_protocol_from: absent -> empty (feature off)") {
    CHECK(Config::from_string("{}").proxy_protocol_from.empty());
}

TEST_CASE("proxy_protocol_from accepts a single string") {
    const Config c = Config::from_string(R"({"proxy_protocol_from": "10.0.0.5"})");
    REQUIRE(c.proxy_protocol_from.size() == 1);
    CHECK(c.proxy_protocol_from[0] == "10.0.0.5");
}

TEST_CASE("proxy_protocol_from accepts a list, in order") {
    const Config c = Config::from_string(R"({"proxy_protocol_from": ["10.0.0.5", "172.19.0.0/16"]})");
    REQUIRE(c.proxy_protocol_from.size() == 2);
    CHECK(c.proxy_protocol_from[0] == "10.0.0.5");
    CHECK(c.proxy_protocol_from[1] == "172.19.0.0/16");
}

TEST_CASE("the old flat schema is rejected (no backwards-compat bridge)") {
    CHECK_THROWS_AS(Config::from_string(R"({"rpc_url": "http://node:8332", "bind_port": 4444})"),
                    ConfigError);
}

TEST_CASE("unknown keys are rejected") {
    CHECK_THROWS_AS(Config::from_string(R"({"definitely_not_a_key": 1})"), ConfigError);
}

TEST_CASE("a non-object is rejected") {
    CHECK_THROWS_AS(Config::from_string("[]"), ConfigError);
}

TEST_CASE("donation_percent must be within [0, 100]") {
    CHECK_THROWS_AS(Config::from_string(R"({"donation_percent": -1.0})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"donation_percent": 100.5})"), ConfigError);
    // Boundaries are accepted (a non-zero percent needs a donation_address; 0 does not).
    CHECK(Config::from_string(R"({"donation_percent": 0.0})").donation_percent == 0.0);
    CHECK(Config::from_string(R"({"donation_percent": 100.0, "donation_address": "bc1qexample"})")
              .donation_percent == doctest::Approx(100.0));
    CHECK(Config::from_string(R"({"donation_percent": 1.5, "donation_address": "bc1qexample"})")
              .donation_percent == doctest::Approx(1.5));
}

TEST_CASE("maximum_difficulty cannot be below minimum_difficulty") {
    CHECK_THROWS_AS(
        Config::from_string(R"({"minimum_difficulty": 10, "maximum_difficulty": 9})"),
        ConfigError);
    CHECK_NOTHROW(
        Config::from_string(R"({"minimum_difficulty": 10, "maximum_difficulty": 10})"));
    CHECK_NOTHROW(
        Config::from_string(R"({"minimum_difficulty": 10, "maximum_difficulty": 0})"));
}

TEST_CASE("an over-long coinbase_signature is rejected at load") {
    // The default extranonces and work identifier/framing leave 60 bytes for the signature.
    CHECK_THROWS_AS(
        Config::from_string(std::string(R"({"coinbase_signature": ")") + std::string(61, 'x') +
                            R"("})"),
        ConfigError);
    CHECK(Config::from_string(std::string(R"({"coinbase_signature": ")") + std::string(60, 'x') +
                              R"("})")
              .coinbase_signature.size() == 60);
}

TEST_CASE("work_source selects IPC without a separate acknowledgement") {
    CHECK(Config::from_string(R"({"work_source": "ipc"})").work_source == "ipc");
    CHECK(Config::from_string(R"({"work_source": "rpc"})").work_source == "rpc");
    CHECK_THROWS_AS(Config::from_string(R"({"experimental_ipc": true})"), ConfigError);
}

namespace {
// Caller removes the returned path.
std::filesystem::path write_temp(const std::string& name, const std::string& text) {
    const std::filesystem::path path = std::filesystem::temp_directory_path() / name;
    std::ofstream(path, std::ios::binary) << text;
    return path;
}
} // namespace

TEST_CASE("from_file parses a YAML config") {
    // Numbers and booleans stay typed; strings that look numeric are quoted.
    const auto path = write_temp("ep_config_test.yaml", R"(
bitcoin_nodes:
  - address: http://node:8332
    username: u
    password: p
stratum_listen:
  - 0.0.0.0:4444
initial_difficulty: 1024
minimum_difficulty: 0.0001
block_poll_milliseconds: 250
variable_difficulty: false
coinbase_signature: "/test/"
version_rolling_mask: 1fffe000
)");
    const Config config = Config::from_file(path.string());
    CHECK(config.rpc_url == "http://node:8332");
    CHECK(config.rpc_user == "u");
    CHECK(config.bind_port == 4444);
    CHECK(config.initial_difficulty == doctest::Approx(1024.0));
    // A fractional scalar must stay a double, not be truncated to an int (0).
    CHECK(config.minimum_difficulty == doctest::Approx(0.0001));
    CHECK(config.poll_interval == doctest::Approx(0.25)); // 250 ms -> seconds
    CHECK(config.variable_difficulty == false);
    CHECK(config.coinbase_signature == "/test/");
    // A bare hex string (not numeric) stays a string and is parsed base-16.
    CHECK(config.version_rolling_mask == 0x1fffe000u);
    std::filesystem::remove(path);
}

TEST_CASE("max_workers_per_address loads, defaults to 256, and rejects negatives") {
    CHECK(Config::from_string(R"({"max_workers_per_address": 32})").max_workers_per_address == 32);
    CHECK(Config::from_string("{}").max_workers_per_address == 256); // default
    CHECK(Config::from_string(R"({"max_workers_per_address": 0})").max_workers_per_address == 0);
    CHECK_THROWS_AS(Config::from_string(R"({"max_workers_per_address": -1})"), ConfigError);
}

TEST_CASE("user_stats_retention_days loads, defaults to 90, and rejects negatives") {
    CHECK(Config::from_string(R"({"user_stats_retention_days": 30})").user_stats_retention_days == 30);
    CHECK(Config::from_string("{}").user_stats_retention_days == 90); // default
    CHECK(Config::from_string(R"({"user_stats_retention_days": 0})").user_stats_retention_days == 0);
    CHECK_THROWS_AS(Config::from_string(R"({"user_stats_retention_days": -1})"), ConfigError);
    // Upper bound (~100 years): beyond it the file_time_type cutoff arithmetic would overflow.
    CHECK_THROWS_AS(Config::from_string(R"({"user_stats_retention_days": 36501})"), ConfigError);
}

TEST_CASE("YAML quoting preserves scalar types") {
    // A quoted numeric-looking value is an explicit string. For a string-typed key it must
    // survive untouched (a password like "12345" or "true" must never coerce to a number/bool).
    const auto ok_path = write_temp("ep_config_quote_ok.yaml", R"(
coinbase_signature: "12345"
version_rolling_mask: "1fffe000"
)");
    const Config config = Config::from_file(ok_path.string());
    CHECK(config.coinbase_signature == "12345");
    CHECK(config.version_rolling_mask == 0x1fffe000u); // quoted mask string still parses base-16
    std::filesystem::remove(ok_path);

    // For a numeric-typed key a quoted value is a type error, not a silent coercion.
    const auto bad_path = write_temp("ep_config_quote_bad.yaml", R"(
initial_difficulty: "1024"
)");
    CHECK_THROWS_AS(Config::from_file(bad_path.string()), ConfigError);
    std::filesystem::remove(bad_path);
}

TEST_CASE("from_file still reads a JSON config (YAML is a JSON superset)") {
    const auto path = write_temp("ep_config_test.json", R"({
        "bitcoin_nodes": [{"address": "http://node:8332"}],
        "stratum_listen": "0.0.0.0:3333",
        "max_clients": 50
    })");
    const Config config = Config::from_file(path.string());
    CHECK(config.rpc_url == "http://node:8332");
    CHECK(config.bind_port == 3333);
    CHECK(config.max_clients == 50);
    std::filesystem::remove(path);
}

TEST_CASE("from_file throws ConfigError on malformed YAML") {
    const auto path = write_temp("ep_config_bad.yaml", "bitcoin_nodes: [unterminated\n");
    CHECK_THROWS_AS(Config::from_file(path.string()), ConfigError);
    std::filesystem::remove(path);
}

TEST_CASE("from_file throws ConfigError when the file cannot be opened") {
    CHECK_THROWS_AS(Config::from_file("/nonexistent/dir/definitely_absent.yaml"), ConfigError);
}

TEST_CASE("version_rolling_mask accepts both a hex string and a JSON integer") {
    // Bare hex string -> parsed base-16.
    CHECK(Config::from_string(R"({"version_rolling_mask": "1fffe000"})").version_rolling_mask ==
          0x1fffe000u);
    // JSON integer -> taken as-is (within the BIP320 range, no clamp). 0x2000 = 8192.
    CHECK(Config::from_string(R"({"version_rolling_mask": 8192})").version_rolling_mask ==
          0x00002000u);
}

TEST_CASE("extranonce1 prefix decodes from config and leaves a four-byte counter") {
    const Config config = Config::from_string(
        R"({"extranonce1_size": 6, "extranonce1_prefix": "A0b1"})");
    CHECK(util::to_hex(config.extranonce1_prefix) == "a0b1");
    CHECK(config.extranonce1_size - config.extranonce1_prefix.size() == 4);
}

TEST_CASE("version_rolling_mask is clamped to the BIP320 range") {
    // Bits outside 0x1fffe000 would let a miner roll nVersion's high bits -> bad-version blocks.
    CHECK(Config::from_string(R"({"version_rolling_mask": "ffffffff"})").version_rolling_mask ==
          0x1fffe000u);
    // 0x3000 = 12288; bit 12 dropped, bit 13 kept -> 0x2000.
    CHECK(Config::from_string(R"({"version_rolling_mask": 12288})").version_rolling_mask ==
          0x00002000u);
}

TEST_CASE("version_rolling_mask must retain a BIP320 bit") {
    CHECK_THROWS_AS(Config::from_string(R"({"version_rolling_mask": 0})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"version_rolling_mask": "00000000"})"),
                    ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"version_rolling_mask": 4096})"), ConfigError);
}

TEST_CASE("every remaining scalar key maps onto its config field") {
    const Config c = Config::from_string(R"({
        "coinbase_version": 2,
        "variable_difficulty": false,
        "vardiff_target_shares_per_minute": 30,
        "vardiff_retarget_seconds": 120,
        "fast_block_notify": false,
        "status_interval_seconds": 15,
        "stats_directory": "/var/lib/pool",
        "max_line_bytes": 8192,
        "donation_percent": 2.5,
        "donation_address": "bc1qexample"
    })");
    CHECK(c.coinbase_version == 2u);
    CHECK(c.variable_difficulty == false);
    CHECK(c.vardiff_target_shares_per_minute == doctest::Approx(30.0));
    CHECK(c.vardiff_retarget_seconds == 120);
    CHECK(c.fast_block_notify == false);
    CHECK(c.status_interval_seconds == doctest::Approx(15.0));
    CHECK(c.stats_directory == "/var/lib/pool");
    CHECK(c.max_line_bytes == 8192u);
    CHECK(c.donation_percent == doctest::Approx(2.5));
    CHECK(c.donation_address == "bc1qexample");
}

TEST_CASE("api_listen accepts a single string and an array (first entry wins)") {
    CHECK(Config::from_string(R"({"api_listen": "127.0.0.1:9000"})").api_port == 9000);
    const Config c = Config::from_string(R"({"api_listen": ["0.0.0.0:9001", "ignored:1"]})");
    CHECK(c.api_host == "0.0.0.0");
    CHECK(c.api_port == 9001);
}

TEST_CASE("an empty bitcoin_nodes array leaves the RPC defaults in place") {
    const Config c = Config::from_string(R"({"bitcoin_nodes": []})");
    CHECK(c.rpc_url == "http://127.0.0.1:18443"); // default preserved
    CHECK(c.rpc_failover.empty());
}

TEST_CASE("a failover node inherits the primary's credentials when omitted") {
    const Config c = Config::from_string(R"({
        "bitcoin_nodes": [
            {"address": "http://primary:8332", "username": "alice", "password": "secret"},
            {"address": "http://backup:8332"}
        ]
    })");
    REQUIRE(c.rpc_failover.size() == 1);
    CHECK(c.rpc_failover[0].user == "alice");
    CHECK(c.rpc_failover[0].password == "secret");
}

TEST_CASE("block_poll_milliseconds converts to a fractional second poll interval") {
    CHECK(Config::from_string(R"({"block_poll_milliseconds": 500})").poll_interval ==
          doctest::Approx(0.5));
    CHECK(Config::from_string(R"({"block_poll_milliseconds": 1000})").poll_interval ==
          doctest::Approx(1.0));
}

TEST_CASE("worker_threads 0 (auto) is a valid value that survives parsing") {
    CHECK(Config::from_string(R"({"worker_threads": 0})").worker_threads == 0);
    CHECK(Config::from_string(R"({"worker_threads": 12})").worker_threads == 12);
}

TEST_CASE("max_line_bytes must be positive") {
    CHECK_THROWS_AS(Config::from_string(R"({"max_line_bytes": 0})"), ConfigError);
    CHECK_THROWS_AS(
        Config::from_string(R"({"max_line_bytes": 16777216})"),
        ConfigError);
}

TEST_CASE("the scriptSig budget tracks the extranonce sizes, not just the signature length") {
    // Height(10) + extranonces(16) + identifier/framing(18) leaves 56 bytes.
    CHECK_THROWS_AS(
        Config::from_string(std::string(R"({"extranonce1_size": 8, "extranonce2_size": 8, )"
                                        R"("coinbase_signature": ")") +
                            std::string(57, 'x') + R"("})"),
        ConfigError);
    CHECK_NOTHROW(
        Config::from_string(std::string(R"({"extranonce1_size": 8, "extranonce2_size": 8, )"
                                        R"("coinbase_signature": ")") +
                            std::string(56, 'x') + R"("})"));
}

TEST_CASE("rpc_endpoints lists the primary first, then failover in order") {
    const auto endpoints = Config::from_string(R"({
        "bitcoin_nodes": [
            {"address": "p", "username": "pu", "password": "pp"},
            {"address": "a", "username": "au", "password": "ap"},
            {"address": "b", "username": "bu", "password": "bp"}
        ]
    })").rpc_endpoints();
    REQUIRE(endpoints.size() == 3);
    CHECK(endpoints[0].url == "p");
    CHECK(endpoints[0].password == "pp");
    CHECK(endpoints[1].url == "a");
    CHECK(endpoints[2].url == "b");
}

TEST_CASE("runtime-only config changes do not require a restart") {
    const Config current;
    Config replacement = current;
    replacement.initial_difficulty = 64.0;
    replacement.minimum_difficulty = 2.0;
    replacement.maximum_difficulty = 4096.0;
    replacement.variable_difficulty = false;
    replacement.vardiff_target_shares_per_minute = 20.0;
    replacement.vardiff_retarget_seconds = 30;
    replacement.work_rebroadcast_seconds = 15.0;
    replacement.poll_interval = 0.5;
    replacement.status_interval_seconds = 10.0;
    replacement.user_stats_retention_days = 30;
    replacement.fast_block_notify = false;
    replacement.max_clients = 500;
    replacement.max_workers_per_address = 64;
    replacement.drop_idle_seconds = 600;
    replacement.auth_timeout_seconds = 10;
    replacement.max_protocol_errors = 20;

    CHECK(current.restart_required_changes(replacement).empty());
    const RuntimeConfig runtime = replacement.runtime_config();
    CHECK(runtime.initial_difficulty == doctest::Approx(64.0));
    CHECK(runtime.poll_interval == doctest::Approx(0.5));
    CHECK(runtime.max_clients == 500);
    CHECK(runtime.fast_block_notify == false);
}

TEST_CASE("every startup setting is rejected by config reload") {
    struct SettingMutation {
        std::string_view field;
        std::string_view reported_name;
        void (*mutate)(Config&);
    };
    const std::vector<SettingMutation> settings{
        {"rpc_url", "bitcoin_nodes", [](Config& config) { config.rpc_url = "other:8332"; }},
        {"rpc_user", "bitcoin_nodes", [](Config& config) { config.rpc_user = "other"; }},
        {"rpc_password", "bitcoin_nodes", [](Config& config) { config.rpc_password = "other"; }},
        {"rpc_failover", "bitcoin_nodes", [](Config& config) {
             config.rpc_failover.push_back({"backup:8332", "user", "password"});
         }},
        {"bind_host", "stratum_listen", [](Config& config) { config.bind_host = "127.0.0.1"; }},
        {"bind_port", "stratum_listen", [](Config& config) { config.bind_port = 4444; }},
        {"bind_ports", "stratum_listen", [](Config& config) { config.bind_ports = {3333, 4444}; }},
        {"sv2_host", "sv2_listen", [](Config& config) { config.sv2_host = "127.0.0.1"; }},
        {"sv2_ports", "sv2_listen", [](Config& config) { config.sv2_ports = {4333}; }},
        {"sv2_static_secret_key_file", "sv2_static_secret_key_file", [](Config& config) {
             config.sv2_static_secret_key_file = "static.key";
         }},
        {"sv2_authority_public_key_file", "sv2_authority_public_key_file", [](Config& config) {
             config.sv2_authority_public_key_file = "authority.pub";
         }},
        {"sv2_certificate_file", "sv2_certificate_file", [](Config& config) {
             config.sv2_certificate_file = "certificate.bin";
         }},
        {"sv2_plaintext_host", "sv2_plaintext_listen", [](Config& config) {
             config.sv2_plaintext_host = "localhost";
         }},
        {"sv2_plaintext_ports", "sv2_plaintext_listen", [](Config& config) {
             config.sv2_plaintext_ports = {14333};
         }},
        {"proxy_protocol_from", "proxy_protocol_from", [](Config& config) {
             config.proxy_protocol_from = {"127.0.0.1"};
         }},
        {"api_host", "api_listen", [](Config& config) { config.api_host = "0.0.0.0"; }},
        {"api_port", "api_listen", [](Config& config) { config.api_port = 9000; }},
        {"extranonce1_size", "extranonce1_size", [](Config& config) { config.extranonce1_size = 6; }},
        {"extranonce2_size", "extranonce2_size", [](Config& config) { config.extranonce2_size = 4; }},
        {"extranonce1_prefix", "extranonce1_prefix", [](Config& config) {
             config.extranonce1_prefix = {0x00, 0x01};
         }},
        {"coinbase_signature", "coinbase_signature", [](Config& config) {
             config.coinbase_signature = "/replacement/";
         }},
        {"coinbase_version", "coinbase_version", [](Config& config) { config.coinbase_version = 2; }},
        {"donation_percent", "donation_percent", [](Config& config) { config.donation_percent = 1.0; }},
        {"donation_address", "donation_address", [](Config& config) { config.donation_address = "address"; }},
        {"stats_directory", "stats_directory", [](Config& config) {
             config.stats_directory = "/tmp/replacement";
         }},
        {"zmq_block_endpoint", "zmq_block_endpoint", [](Config& config) {
             config.zmq_block_endpoint = "tcp://node:28332";
         }},
        {"work_source", "work_source", [](Config& config) { config.work_source = "ipc"; }},
        {"ipc_socket_path", "ipc_socket_path", [](Config& config) {
             config.ipc_socket_path = "/tmp/replacement.sock";
         }},
        {"max_line_bytes", "max_line_bytes", [](Config& config) { config.max_line_bytes = 8192; }},
        {"worker_threads", "worker_threads", [](Config& config) { config.worker_threads = 4; }},
        {"version_rolling_mask", "version_rolling_mask", [](Config& config) {
             config.version_rolling_mask = 0x00002000u;
         }},
    };
    const Config current;
    for (const auto& setting : settings) {
        CAPTURE(setting.field);
        Config replacement = current;
        setting.mutate(replacement);
        CHECK(current.restart_required_changes(replacement) ==
              std::vector<std::string>{std::string(setting.reported_name)});
    }
}

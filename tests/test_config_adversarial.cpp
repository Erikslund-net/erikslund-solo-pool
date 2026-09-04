// Adversarial / negative coverage for Config::from_string / from_file: malformed input must be
// rejected by throwing (ConfigError where noted, otherwise some std::exception), never crash.
#include <doctest/doctest.h>

#include <exception>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "core/config.hpp"
#include "core/errors.hpp"

using namespace erikslund;

TEST_CASE("non-object top-level config is a ConfigError") {
    CHECK_THROWS_AS(Config::from_string("[]"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"("a string")"), ConfigError);
    CHECK_THROWS_AS(Config::from_string("42"), ConfigError);
    CHECK_THROWS_AS(Config::from_string("true"), ConfigError);
    CHECK_THROWS_AS(Config::from_string("null"), ConfigError);
}

TEST_CASE("any unknown key is a ConfigError") {
    for (const char* key : {"definitely_not_a_key", "rpc_url", "bind_port", "logdir",
                            "btcd", "Coinbase_Signature", "stratum_port"}) {
        const std::string text = std::string("{\"") + key + "\": \"x\"}";
        CAPTURE(key);
        CHECK_THROWS_AS(Config::from_string(text), ConfigError);
    }
}

TEST_CASE("the legacy flat schema (rpc_url / bind_port) is rejected outright") {
    CHECK_THROWS_AS(Config::from_string(R"({"rpc_url":"http://node:8332","bind_port":4444})"),
                    ConfigError);
}

TEST_CASE("donation_percent outside [0,100] is a ConfigError; the boundaries pass") {
    CHECK_THROWS_AS(Config::from_string(R"({"donation_percent": -0.01})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"donation_percent": -100.0})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"donation_percent": 100.01})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"donation_percent": 1000.0})"), ConfigError);
    CHECK_NOTHROW(Config::from_string(R"({"donation_percent": 0.0})"));
    CHECK_NOTHROW(
        Config::from_string(R"({"donation_percent": 100.0, "donation_address": "bc1qexample"})"));
}

TEST_CASE("donation_percent > 0 with no donation_address is a ConfigError (fail-closed)") {
    // The bug this guards: a non-zero percent with an empty address silently disabled donation
    // (coinbase pays 100% to the miner) with no warning.
    CHECK_THROWS_AS(Config::from_string(R"({"donation_percent": 1.0})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"donation_percent": 1.0, "donation_address": ""})"),
                    ConfigError);
    // 0% needs no address; a non-zero percent WITH an address is fine.
    CHECK_NOTHROW(Config::from_string(R"({"donation_percent": 0.0})"));
    CHECK_NOTHROW(
        Config::from_string(R"({"donation_percent": 5.0, "donation_address": "bc1qexample"})"));
}

TEST_CASE("an over-long coinbase_signature (no room in the 100-byte scriptSig) is a ConfigError") {
    // Height(10) + extranonces(12) + identifier/framing(18) leaves 60 bytes.
    CHECK_THROWS_AS(Config::from_string(std::string(R"({"coinbase_signature": ")") +
                                        std::string(61, 'x') + R"("})"),
                    ConfigError);
    CHECK_THROWS_AS(Config::from_string(std::string(R"({"coinbase_signature": ")") +
                                        std::string(500, 'x') + R"("})"),
                    ConfigError);
    CHECK_NOTHROW(Config::from_string(std::string(R"({"coinbase_signature": ")") +
                                      std::string(60, 'x') + R"("})"));
}

TEST_CASE("the scriptSig budget also reflects larger extranonce sizes") {
    // Larger extranonces leave 56 bytes for the signature.
    CHECK_THROWS_AS(
        Config::from_string(std::string(R"({"extranonce1_size": 8, "extranonce2_size": 8, )"
                                        R"("coinbase_signature": ")") +
                            std::string(57, 'x') + R"("})"),
        ConfigError);
}

TEST_CASE("a bitcoin_nodes entry missing the required address throws") {
    // Glaze leaves the (non-optional) address empty when absent; config_from rejects an empty one.
    CHECK_THROWS(Config::from_string(R"({"bitcoin_nodes":[{"username":"u","password":"p"}]})"));
}

TEST_CASE("version_rolling_mask as non-hex is a ConfigError") {
    CHECK_THROWS_AS(Config::from_string(R"({"version_rolling_mask": "nothex"})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"version_rolling_mask": "zzzzzzzz"})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"version_rolling_mask": "!!!!"})"), ConfigError);
}

TEST_CASE("version_rolling_mask: a hex string with trailing junk parses its prefix (no throw)") {
    // std::stoul stops at the first non-hex char, so "1fffe000xyz" -> 0x1fffe000.
    CHECK_NOTHROW(Config::from_string(R"({"version_rolling_mask": "1fffe000xyz"})"));
    CHECK(Config::from_string(R"({"version_rolling_mask": "1fffe000xyz"})").version_rolling_mask ==
          0x1fffe000u);
}

TEST_CASE("version_rolling_mask: an over-uint32 hex value is truncated, not rejected") {
    // stoul yields a wider integer; the static_cast<uint32_t> truncates -- no throw.
    CHECK_NOTHROW(Config::from_string(R"({"version_rolling_mask": "1ffffffff"})"));
}

TEST_CASE("a stratum_listen port that is not a number is a ConfigError") {
    CHECK_THROWS_AS(Config::from_string(R"({"stratum_listen":"0.0.0.0:notaport"})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"stratum_listen":["0.0.0.0:xyz"]})"), ConfigError);
}

TEST_CASE("a stratum_listen with NO ':' is a ConfigError (no silent ephemeral-port bind)") {
    // A listen address must carry an explicit port; a missing one would bind an arbitrary
    // ephemeral port no miner could reach.
    CHECK_THROWS_AS(Config::from_string(R"({"stratum_listen":"justhostname"})"), ConfigError);
}

TEST_CASE("a stratum_listen port of 0 or out of range is a ConfigError") {
    CHECK_THROWS_AS(Config::from_string(R"({"stratum_listen":"0.0.0.0:0"})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"stratum_listen":"0.0.0.0:70000"})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"stratum_listen":"0.0.0.0:3333x"})"),
                    ConfigError); // trailing garbage rejected
}

TEST_CASE("multi-entry stratum_listen with differing hosts is a ConfigError") {
    // Only one bind host is honored, so differing per-entry hosts must be rejected, not dropped.
    CHECK_THROWS_AS(
        Config::from_string(R"({"stratum_listen":["0.0.0.0:3333","127.0.0.1:4001"]})"), ConfigError);
    // Same host across entries is fine.
    const Config c =
        Config::from_string(R"({"stratum_listen":["0.0.0.0:3333","0.0.0.0:4001"]})");
    CHECK(c.bind_host == "0.0.0.0");
    CHECK(c.bind_ports == std::vector<uint16_t>{3333, 4001});
}

TEST_CASE("an empty stratum_listen array leaves the defaults untouched (no crash)") {
    const Config c = Config::from_string(R"({"stratum_listen": []})");
    CHECK(c.bind_port == 3333); // default preserved
}

TEST_CASE("a wrong-typed scalar is a ConfigError") {
    CHECK_THROWS_AS(Config::from_string(R"({"extranonce2_size": "eight"})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"max_clients": "many"})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"initial_difficulty": "hard"})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"variable_difficulty": "yes"})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"block_poll_milliseconds": "soon"})"), ConfigError);
}

TEST_CASE("a non-string coinbase_signature: Glaze coerces a number, rejects a structure") {
    // BEHAVIOR CHANGE under the Glaze migration: a JSON number is coerced to its string form
    // rather than rejected (the pre-Glaze typed path threw). An array/object still cannot coerce.
    CHECK(Config::from_string(R"({"coinbase_signature": 12345})").coinbase_signature == "12345");
    CHECK_THROWS_AS(Config::from_string(R"({"coinbase_signature": ["a"]})"), ConfigError);
}

TEST_CASE("from_file throws ConfigError on a missing file") {
    CHECK_THROWS_AS(Config::from_file("/nonexistent/definitely/absent_config.yaml"), ConfigError);
}

TEST_CASE("from_file throws ConfigError on malformed YAML") {
    const std::filesystem::path path =
        std::filesystem::temp_directory_path() / "ep_adv_bad_config.yaml";
    std::ofstream(path, std::ios::binary) << "stratum_listen: [unterminated\n";
    CHECK_THROWS_AS(Config::from_file(path.string()), ConfigError);
    std::filesystem::remove(path);
}

TEST_CASE("from_file rejects a config file whose root is not a mapping") {
    // A YAML sequence at the document root cannot read into the ConfigFile object -> ConfigError.
    const std::filesystem::path path =
        std::filesystem::temp_directory_path() / "ep_adv_seq_config.yaml";
    std::ofstream(path, std::ios::binary) << "- a\n- b\n";
    CHECK_THROWS_AS(Config::from_file(path.string()), ConfigError);
    std::filesystem::remove(path);
}

TEST_CASE("out-of-range numeric values are a ConfigError (schema bounds enforced)") {
    // Out-of-range values would otherwise busy-loop, divide by zero, or reject every share:
    // fail fast at load instead.
    CHECK_THROWS_AS(Config::from_string(R"({"initial_difficulty": 0.0})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"initial_difficulty": -1.0})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"minimum_difficulty": 0.0})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"minimum_difficulty": -0.5})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"maximum_difficulty": -0.1})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"vardiff_target_shares_per_minute": 0.0})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"vardiff_retarget_seconds": 0})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"work_rebroadcast_seconds": 0})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"block_poll_milliseconds": 0})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"extranonce1_size": 1})"), ConfigError);
    // Min 4: a 2-3 byte extranonce1 space can wrap on a long-lived pool, handing two
    // concurrent miners identical search space.
    CHECK_THROWS_AS(Config::from_string(R"({"extranonce1_size": 2})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"extranonce1_size": 3})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"extranonce1_size": 9})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"extranonce1_prefix": "0"})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"extranonce1_prefix": "00gg"})"), ConfigError);
    CHECK_THROWS_AS(
        Config::from_string(R"({"extranonce1_size": 4, "extranonce1_prefix": "00"})"),
        ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"extranonce2_size": 0})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"extranonce2_size": 9})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"max_clients": -1})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"drop_idle_seconds": -1})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"auth_timeout_seconds": -1})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"max_protocol_errors": -1})"), ConfigError);
    CHECK_THROWS_AS(Config::from_string(R"({"status_interval_seconds": -1.0})"), ConfigError);
}

TEST_CASE("schema-boundary numeric values are accepted") {
    CHECK_NOTHROW(Config::from_string(R"({"extranonce1_size": 4})"));
    CHECK_NOTHROW(Config::from_string(R"({"extranonce1_size": 8})"));
    CHECK_NOTHROW(
        Config::from_string(R"({"extranonce1_size": 6, "extranonce1_prefix": "0001"})"));
    CHECK_NOTHROW(Config::from_string(R"({"extranonce2_size": 8})"));
    CHECK_NOTHROW(Config::from_string(R"({"vardiff_retarget_seconds": 1})"));
    CHECK_NOTHROW(Config::from_string(R"({"work_rebroadcast_seconds": 1})"));
    CHECK_NOTHROW(Config::from_string(R"({"block_poll_milliseconds": 1})"));
    CHECK_NOTHROW(Config::from_string(R"({"maximum_difficulty": 0.0})"));    // 0 = no cap
    CHECK_NOTHROW(Config::from_string(R"({"drop_idle_seconds": 0})"));       // 0 = never
    CHECK_NOTHROW(Config::from_string(R"({"auth_timeout_seconds": 0})"));    // 0 = never
    CHECK_NOTHROW(Config::from_string(R"({"status_interval_seconds": 0.0})"));
}

TEST_CASE("a valid minimal config still parses after all the negative probing") {
    // Sanity: the happy path is unaffected.
    const Config c = Config::from_string(R"({"bitcoin_nodes":[{"address":"http://n:8332"}],
                                            "stratum_listen":"0.0.0.0:3333"})");
    CHECK(c.rpc_url == "http://n:8332");
    CHECK(c.bind_port == 3333);
}

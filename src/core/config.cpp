#include "core/config.hpp"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <glaze/glaze.hpp>
#include <glaze/yaml.hpp>

#include "bitcoin/coinbase.hpp"
#include "core/errors.hpp"
#include "core/logging.hpp"
#include "mining/work_identity.hpp"
#include "util/hex.hpp"

namespace erikslund {

// Glaze reflection requires these file-private wire types to have external linkage.
namespace config_detail {

struct NodeEntry {
    std::string address;
    std::optional<std::string> username;
    std::optional<std::string> password;
    std::optional<bool> notify;
};
using ScalarOrList = std::variant<std::string, std::vector<std::string>>;

struct ConfigFile {
    std::optional<std::vector<NodeEntry>> bitcoin_nodes;
    std::optional<ScalarOrList> stratum_listen;
    std::optional<ScalarOrList> sv2_listen;
    std::optional<std::string> sv2_static_secret_key_file;
    std::optional<std::string> sv2_authority_public_key_file;
    std::optional<std::string> sv2_certificate_file;
    std::optional<ScalarOrList> sv2_plaintext_listen;
    std::optional<ScalarOrList> api_listen;
    std::optional<ScalarOrList> proxy_protocol_from;
    std::optional<std::string> coinbase_signature;
    std::optional<std::uint32_t> coinbase_version;
    std::optional<double> initial_difficulty;
    std::optional<double> minimum_difficulty;
    std::optional<double> maximum_difficulty;
    std::optional<bool> variable_difficulty;
    std::optional<double> vardiff_target_shares_per_minute;
    std::optional<int> vardiff_retarget_seconds;
    std::optional<std::size_t> extranonce1_size;
    std::optional<std::size_t> extranonce2_size;
    std::optional<std::string> extranonce1_prefix;
    std::optional<std::string> zmq_block_endpoint;
    std::optional<bool> fast_block_notify;
    std::optional<std::string> work_source;
    std::optional<std::string> ipc_socket_path;
    std::optional<double> block_poll_milliseconds;
    std::optional<double> work_rebroadcast_seconds;
    std::optional<std::variant<std::uint32_t, std::string>> version_rolling_mask;
    std::optional<double> donation_percent;
    std::optional<std::string> donation_address;
    std::optional<int> max_clients;
    std::optional<int> max_workers_per_address;
    std::optional<int> drop_idle_seconds;
    std::optional<std::size_t> max_line_bytes;
    std::optional<int> auth_timeout_seconds;
    std::optional<int> max_protocol_errors;
    std::optional<std::string> stats_directory;
    std::optional<double> status_interval_seconds;
    std::optional<int> user_stats_retention_days;
    std::optional<int> worker_threads;
};

} // namespace config_detail

namespace {

using config_detail::ConfigFile;
using config_detail::ScalarOrList;

std::pair<std::string, uint16_t> split_host_port(const std::string& host_port) {
    const auto colon = host_port.rfind(':');
    if (colon == std::string::npos)
        throw ConfigError("listen address has no port (expected host:port or :port): " + host_port);
    const std::string port_str = host_port.substr(colon + 1);
    // Require a clean 1..65535 (reject truncation, trailing garbage, and port 0).
    uint32_t port = 0;
    const char* begin = port_str.data();
    const char* end = begin + port_str.size();
    const auto [ptr, ec] = std::from_chars(begin, end, port);
    if (ec != std::errc{} || ptr != end || port < 1 || port > 65535)
        throw ConfigError("invalid port in listen address: " + host_port);
    return {host_port.substr(0, colon), static_cast<uint16_t>(port)};
}

// Range checks + clamps applied after a Config is populated from the parsed file.
void finalize_and_validate(Config& config) {
    const std::uint32_t rollable = config.version_rolling_mask & 0x1fffe000u;
    if (rollable == 0)
        throw ConfigError("version_rolling_mask must set at least one BIP320 bit (1fffe000)");
    if (rollable != config.version_rolling_mask) {
        log::warning("version_rolling_mask {:08x} has bits outside the BIP320 range; using {:08x}",
                     config.version_rolling_mask, rollable);
        config.version_rolling_mask = rollable;
    }

    const int noise_credential_file_count =
        static_cast<int>(!config.sv2_static_secret_key_file.empty()) +
        static_cast<int>(!config.sv2_authority_public_key_file.empty()) +
        static_cast<int>(!config.sv2_certificate_file.empty());
    if (noise_credential_file_count != 0 &&
        noise_credential_file_count != 3)
        throw ConfigError("SV2 Noise credentials require all three of "
                          "sv2_static_secret_key_file, sv2_authority_public_key_file, and "
                          "sv2_certificate_file");
    if (!config.sv2_ports.empty() && noise_credential_file_count != 3)
        throw ConfigError("sv2_listen requires all three SV2 Noise credential files");
    if (!config.sv2_plaintext_ports.empty() &&
        config.sv2_plaintext_host != "127.0.0.1")
        throw ConfigError("sv2_plaintext_listen is development-only and must bind 127.0.0.1");
    if (std::ranges::any_of(
            config.sv2_ports, [&](uint16_t port) {
                return std::ranges::contains(config.sv2_plaintext_ports,
                                             port);
            }))
        throw ConfigError(
            "sv2_listen and sv2_plaintext_listen must not overlap; "
            "use distinct ports");

    if (config.donation_percent < 0.0 || config.donation_percent > 100.0)
        throw ConfigError("donation_percent must be in [0.0, 100.0]");
    if (config.donation_percent > 0.0 && config.donation_address.empty())
        throw ConfigError("donation_percent > 0 requires a donation_address");

    if (config.initial_difficulty <= 0.0)
        throw ConfigError("initial_difficulty must be > 0");
    if (config.minimum_difficulty <= 0.0)
        throw ConfigError("minimum_difficulty must be > 0");
    if (config.maximum_difficulty < 0.0)
        throw ConfigError("maximum_difficulty must be >= 0 (0 = no maximum)");
    if (config.maximum_difficulty > 0.0 &&
        config.maximum_difficulty < config.minimum_difficulty)
        throw ConfigError("maximum_difficulty must be >= minimum_difficulty (or 0 for no maximum)");
    if (config.vardiff_target_shares_per_minute <= 0.0)
        throw ConfigError("vardiff_target_shares_per_minute must be > 0");
    if (config.vardiff_retarget_seconds < 1)
        throw ConfigError("vardiff_retarget_seconds must be >= 1");
    if (config.work_rebroadcast_seconds < 1.0)
        throw ConfigError("work_rebroadcast_seconds must be >= 1");
    if (config.work_source != "rpc" && config.work_source != "ipc")
        throw ConfigError("work_source must be \"rpc\" or \"ipc\"");
    if (config.work_source == "ipc" && config.ipc_socket_path.empty())
        throw ConfigError("work_source: ipc requires a non-empty ipc_socket_path");
    if (config.poll_interval <= 0.0)
        throw ConfigError("block_poll_milliseconds must be >= 1");
    // Reserve enough session IDs for sustained connection churn.
    if (config.extranonce1_size < 4 || config.extranonce1_size > 8)
        throw ConfigError("extranonce1_size must be in [4, 8]");
    if (config.extranonce1_prefix.size() > config.extranonce1_size - 4)
        throw ConfigError("extranonce1_prefix must leave at least 4 counter bytes");
    if (config.extranonce2_size < 2 || config.extranonce2_size > 8)
        throw ConfigError("extranonce2_size must be in [2, 8]");
    if (config.status_interval_seconds < 0.0)
        throw ConfigError("status_interval_seconds must be >= 0");
    // Cap ~100 years: beyond ~106751 days the seconds overflow file_time_type's nanosecond int64.
    if (config.user_stats_retention_days < 0 || config.user_stats_retention_days > 36500)
        throw ConfigError("user_stats_retention_days must be in [0, 36500] (0 keeps files forever)");
    if (config.max_clients < 0)
        throw ConfigError("max_clients must be >= 0");
    if (config.max_workers_per_address < 0)
        throw ConfigError("max_workers_per_address must be >= 0 (0 = unlimited)");
    if (config.max_line_bytes < 1 || config.max_line_bytes > 0x00ffffffu)
        throw ConfigError("max_line_bytes must be in [1, 16777215]");
    if (config.drop_idle_seconds < 0)
        throw ConfigError("drop_idle_seconds must be >= 0");
    if (config.auth_timeout_seconds < 0)
        throw ConfigError("auth_timeout_seconds must be >= 0");
    if (config.max_protocol_errors < 0)
        throw ConfigError("max_protocol_errors must be >= 0");

    const size_t scriptsig_budget =
        bitcoin::kMaxHeightPush + config.extranonce1_size + config.extranonce2_size +
        config.coinbase_signature.size() + mining::kWorkIdentifierScriptBudget;
    if (scriptsig_budget > bitcoin::kMaxScriptSig)
        throw ConfigError("coinbase_signature too long: it must leave room in the " +
                          std::to_string(bitcoin::kMaxScriptSig) +
                          "-byte coinbase scriptSig for the height, extranonces, and work identifier");
}

std::vector<std::string> to_list(const ScalarOrList& value) {
    if (const auto* one = std::get_if<std::string>(&value))
        return {*one};
    return std::get<std::vector<std::string>>(value);
}

void parse_listen(const std::optional<ScalarOrList>& entry, std::string_view option,
                  std::string_view default_host, std::string& host,
                  std::vector<uint16_t>& ports) {
    if (!entry)
        return;
    const auto urls = to_list(*entry);
    if (urls.empty())
        return;
    host = split_host_port(urls[0]).first;
    if (host.empty())
        host = default_host;
    ports.clear();
    for (const auto& url : urls) {
        auto [url_host, port] = split_host_port(url);
        if (url_host.empty())
            url_host = default_host;
        if (url_host != host)
            throw ConfigError(std::string(option) + " entries must all use the same host "
                              "(per-port hosts are not supported): " + url);
        ports.push_back(port);
    }
}

Config config_from(const ConfigFile& file) {
    Config config;

    if (file.bitcoin_nodes && !file.bitcoin_nodes->empty()) {
        const auto& nodes = *file.bitcoin_nodes;
        if (nodes[0].address.empty())
            throw ConfigError("bitcoin_nodes[0] requires an address");
        config.rpc_url = nodes[0].address;
        config.rpc_user = nodes[0].username.value_or(std::string{});
        config.rpc_password = nodes[0].password.value_or(std::string{});
        for (std::size_t i = 1; i < nodes.size(); ++i) {
            if (nodes[i].address.empty())
                throw ConfigError("a bitcoin_nodes entry requires an address");
            config.rpc_failover.push_back({nodes[i].address,
                                           nodes[i].username.value_or(config.rpc_user),
                                           nodes[i].password.value_or(config.rpc_password)});
        }
    }

    if (file.stratum_listen) {
        const auto urls = to_list(*file.stratum_listen);
        if (!urls.empty()) {
            config.bind_host = split_host_port(urls[0]).first;
            config.bind_ports.clear();
            for (const auto& url : urls) {
                const auto [host, port] = split_host_port(url);
                if (host != config.bind_host)
                    throw ConfigError("stratum_listen entries must all use the same host "
                                      "(per-port hosts are not supported): " + url);
                config.bind_ports.push_back(port);
            }
            config.bind_port = config.bind_ports.front();
        }
    }

    parse_listen(file.sv2_listen, "sv2_listen", "0.0.0.0", config.sv2_host, config.sv2_ports);
    parse_listen(file.sv2_plaintext_listen, "sv2_plaintext_listen", "127.0.0.1",
                 config.sv2_plaintext_host, config.sv2_plaintext_ports);

    if (file.api_listen) {
        const auto entries = to_list(*file.api_listen);
        if (!entries.empty()) {
            const auto [host, port] = split_host_port(entries[0]);
            // Omitted host means loopback, not 0.0.0.0, so the API is not silently exposed.
            config.api_host = host.empty() ? std::string("127.0.0.1") : host;
            config.api_port = port;
        }
    }

    if (file.proxy_protocol_from)
        config.proxy_protocol_from = to_list(*file.proxy_protocol_from);

    const auto apply = [](auto& field, const auto& opt) {
        if (opt)
            field = *opt;
    };
    apply(config.coinbase_signature, file.coinbase_signature);
    apply(config.coinbase_version, file.coinbase_version);
    apply(config.initial_difficulty, file.initial_difficulty);
    apply(config.minimum_difficulty, file.minimum_difficulty);
    apply(config.maximum_difficulty, file.maximum_difficulty);
    apply(config.variable_difficulty, file.variable_difficulty);
    apply(config.vardiff_target_shares_per_minute, file.vardiff_target_shares_per_minute);
    apply(config.vardiff_retarget_seconds, file.vardiff_retarget_seconds);
    apply(config.extranonce1_size, file.extranonce1_size);
    apply(config.extranonce2_size, file.extranonce2_size);
    apply(config.zmq_block_endpoint, file.zmq_block_endpoint);
    apply(config.fast_block_notify, file.fast_block_notify);
    apply(config.work_source, file.work_source);
    apply(config.ipc_socket_path, file.ipc_socket_path);
    apply(config.sv2_static_secret_key_file, file.sv2_static_secret_key_file);
    apply(config.sv2_authority_public_key_file, file.sv2_authority_public_key_file);
    apply(config.sv2_certificate_file, file.sv2_certificate_file);
    apply(config.work_rebroadcast_seconds, file.work_rebroadcast_seconds);
    apply(config.donation_percent, file.donation_percent);
    apply(config.donation_address, file.donation_address);
    apply(config.max_clients, file.max_clients);
    apply(config.max_workers_per_address, file.max_workers_per_address);
    apply(config.drop_idle_seconds, file.drop_idle_seconds);
    apply(config.max_line_bytes, file.max_line_bytes);
    apply(config.auth_timeout_seconds, file.auth_timeout_seconds);
    apply(config.max_protocol_errors, file.max_protocol_errors);
    apply(config.stats_directory, file.stats_directory);
    apply(config.status_interval_seconds, file.status_interval_seconds);
    apply(config.user_stats_retention_days, file.user_stats_retention_days);
    apply(config.worker_threads, file.worker_threads);

    if (file.extranonce1_prefix) {
        const std::string& prefix = *file.extranonce1_prefix;
        if (!prefix.empty() && !util::is_hex(prefix))
            throw ConfigError("extranonce1_prefix must be an even-length hex string");
        config.extranonce1_prefix = util::from_hex(prefix);
    }

    if (file.block_poll_milliseconds)
        config.poll_interval = *file.block_poll_milliseconds / 1000.0;

    if (file.version_rolling_mask) {
        if (const auto* num = std::get_if<std::uint32_t>(&*file.version_rolling_mask)) {
            config.version_rolling_mask = *num;
        } else {
            try {
                config.version_rolling_mask = static_cast<std::uint32_t>(
                    std::stoul(std::get<std::string>(*file.version_rolling_mask), nullptr, 16));
            } catch (const std::exception&) {
                throw ConfigError("invalid version_rolling_mask");
            }
        }
    }

    finalize_and_validate(config);
    return config;
}

} // namespace

RuntimeConfig Config::runtime_config() const {
    return {
        .initial_difficulty = initial_difficulty,
        .minimum_difficulty = minimum_difficulty,
        .maximum_difficulty = maximum_difficulty,
        .variable_difficulty = variable_difficulty,
        .vardiff_target_shares_per_minute = vardiff_target_shares_per_minute,
        .vardiff_retarget_seconds = vardiff_retarget_seconds,
        .work_rebroadcast_seconds = work_rebroadcast_seconds,
        .poll_interval = poll_interval,
        .status_interval_seconds = status_interval_seconds,
        .user_stats_retention_days = user_stats_retention_days,
        .fast_block_notify = fast_block_notify,
        .max_clients = max_clients,
        .max_workers_per_address = max_workers_per_address,
        .drop_idle_seconds = drop_idle_seconds,
        .auth_timeout_seconds = auth_timeout_seconds,
        .max_protocol_errors = max_protocol_errors,
    };
}

std::vector<std::string> Config::restart_required_changes(const Config& replacement) const {
    std::vector<std::string> changes;
    const auto changed = [&changes](bool differs, std::string_view name) {
        if (differs)
            changes.emplace_back(name);
    };
    const auto endpoints_equal = [](const auto& left, const auto& right) {
        if (left.size() != right.size())
            return false;
        for (std::size_t index = 0; index < left.size(); ++index) {
            if (left[index].url != right[index].url || left[index].user != right[index].user ||
                left[index].password != right[index].password)
                return false;
        }
        return true;
    };

    changed(!endpoints_equal(rpc_endpoints(), replacement.rpc_endpoints()), "bitcoin_nodes");
    changed(bind_host != replacement.bind_host || bind_port != replacement.bind_port ||
                bind_ports != replacement.bind_ports,
            "stratum_listen");
    changed(sv2_host != replacement.sv2_host || sv2_ports != replacement.sv2_ports, "sv2_listen");
    changed(sv2_static_secret_key_file != replacement.sv2_static_secret_key_file,
            "sv2_static_secret_key_file");
    changed(sv2_authority_public_key_file != replacement.sv2_authority_public_key_file,
            "sv2_authority_public_key_file");
    changed(sv2_certificate_file != replacement.sv2_certificate_file, "sv2_certificate_file");
    changed(sv2_plaintext_host != replacement.sv2_plaintext_host ||
                sv2_plaintext_ports != replacement.sv2_plaintext_ports,
            "sv2_plaintext_listen");
    changed(proxy_protocol_from != replacement.proxy_protocol_from, "proxy_protocol_from");
    changed(api_host != replacement.api_host || api_port != replacement.api_port, "api_listen");
    changed(extranonce1_size != replacement.extranonce1_size, "extranonce1_size");
    changed(extranonce2_size != replacement.extranonce2_size, "extranonce2_size");
    changed(extranonce1_prefix != replacement.extranonce1_prefix, "extranonce1_prefix");
    changed(coinbase_signature != replacement.coinbase_signature, "coinbase_signature");
    changed(coinbase_version != replacement.coinbase_version, "coinbase_version");
    changed(donation_percent != replacement.donation_percent, "donation_percent");
    changed(donation_address != replacement.donation_address, "donation_address");
    changed(stats_directory != replacement.stats_directory, "stats_directory");
    changed(zmq_block_endpoint != replacement.zmq_block_endpoint, "zmq_block_endpoint");
    changed(work_source != replacement.work_source, "work_source");
    changed(ipc_socket_path != replacement.ipc_socket_path, "ipc_socket_path");
    changed(max_line_bytes != replacement.max_line_bytes, "max_line_bytes");
    changed(worker_threads != replacement.worker_threads, "worker_threads");
    changed(version_rolling_mask != replacement.version_rolling_mask, "version_rolling_mask");
    return changes;
}

Config Config::from_string(const std::string& text) {
    ConfigFile file;
    if (const auto ec = glz::read_yaml(file, text))
        throw ConfigError("invalid config: " + glz::format_error(ec, text));
    return config_from(file);
}

Config Config::from_file(const std::string& path) {
    std::ifstream stream(path);
    if (!stream)
        throw ConfigError("cannot open config file: " + path);
    std::stringstream buffer;
    buffer << stream.rdbuf();
    return from_string(buffer.str());
}

} // namespace erikslund

#include "stats/poolstatus.hpp"

#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <glaze/glaze.hpp>
#include <yaml-cpp/yaml.h>

#include "core/logging.hpp"
#include "stats/hashrate.hpp"
#include "util/json_number.hpp"

namespace erikslund::stats {

namespace {

// A payout address becomes a filename (users/<address>); re-check at the write choke point
// (charset only, never "." / "..") to block path-injection via a crafted authorize username.
bool is_safe_address(const std::string& address) {
    static constexpr std::string_view kAddressChars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
    return !address.empty() && address.size() <= 100 && address != "." && address != ".." &&
           address.find_first_not_of(kAddressChars) == std::string::npos;
}


std::atomic<uint64_t> g_tmp_counter{0}; // keeps atomic_write temp names unique across threads

void atomic_write(const std::filesystem::path& path, const std::string& text) {
    // Skip the write when content is unchanged: not bumping mtime lets the stats portal's
    // mtime-skip avoid re-ingesting unchanged data every cycle.
    {
        std::ifstream existing(path, std::ios::binary);
        if (existing) {
            std::stringstream buffer;
            buffer << existing.rdbuf();
            if (buffer.str() == text)
                return;
        }
    }
    std::filesystem::create_directories(path.parent_path());
    // pid + per-process counter: two threads writing the same path can't collide on the temp
    // name, which could rename a truncated temp over good data.
    const std::filesystem::path temp_path = path.string() + ".tmp." +
                                            std::to_string(static_cast<long>(::getpid())) + "." +
                                            std::to_string(g_tmp_counter.fetch_add(1));
    try {
        {
            errno = 0;
            std::ofstream out(temp_path, std::ios::binary);
            if (!out)
                throw std::runtime_error("open " + temp_path.string() + ": " +
                                         std::generic_category().message(errno ? errno : EIO));
            out << text;
            out.flush();
            if (!out)
                throw std::runtime_error("write " + temp_path.string() + ": " +
                                         std::generic_category().message(errno ? errno : EIO));
        }
        std::filesystem::rename(temp_path, path);
    } catch (...) {
        std::error_code ec;
        std::filesystem::remove(temp_path, ec); // leave the previous good file untouched
        throw;
    }
}

// Render a glz::generic value as YAML through yaml-cpp's Emitter (the API serves JSON; disk is
// YAML).
void emit_json_as_yaml(YAML::Emitter& out, const glz::generic& value) {
    if (value.is_object()) {
        out << YAML::BeginMap;
        for (const auto& [key, child] : value.get_object()) {
            out << YAML::Key << key << YAML::Value;
            emit_json_as_yaml(out, child);
        }
        out << YAML::EndMap;
    } else if (value.is_array()) {
        out << YAML::BeginSeq;
        for (const auto& element : value.get_array())
            emit_json_as_yaml(out, element);
        out << YAML::EndSeq;
    } else if (value.is_string()) {
        out << value.get<std::string>();
    } else if (value.is_boolean()) {
        out << value.get<bool>();
    } else if (value.is_number()) {
        out << value.get<double>();
    } else {
        out << YAML::Null;
    }
}

std::string to_yaml(const glz::generic& value) {
    YAML::Emitter out;
    emit_json_as_yaml(out, value);
    return std::string(out.c_str()) + "\n";
}

// Days since 1970-01-01 from a Gregorian Y-M-D (Howard Hinnant's algorithm).
int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const auto yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

// Per-window diff/s -> {"hashrate1m": "43.4M", ...} in H/s.
glz::generic hashrate_fields(const std::array<double, kHashrateWindows.size()>& windows) {
    glz::generic out = glz::generic::object_t{};
    for (std::size_t i = 0; i < kHashrateWindows.size(); ++i)
        out[std::string("hashrate") + kHashrateLabels[i]] =
            suffix_string(windows[i] * kHashesPerDiff1Share);
    return out;
}

double round5(double value) {
    return std::round(value * 1e5) / 1e5;
}

using util::format_json_number;

} // namespace

// RFC 9557 / RFC 3339 UTC timestamp -> epoch (0 if unparseable). Trailing 'Z' and [tz] are
// ignored; components read as UTC.
int64_t parse_rfc9557(const std::string& value) {
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (std::sscanf(value.c_str(), "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute,
                    &second) != 6)
        return 0;
    if (month < 1 || month > 12 || day < 1 || day > 31)
        return 0;
    return days_from_civil(year, static_cast<unsigned>(month), static_cast<unsigned>(day)) * 86400 +
           static_cast<int64_t>(hour) * 3600 + static_cast<int64_t>(minute) * 60 + second;
}

double parse_suffix(std::string_view text) {
    // strtod needs a NUL-terminated buffer; status-file values are short.
    std::string buffer(text);
    const size_t start = buffer.find_first_not_of(" 	");
    if (start == std::string::npos)
        return 0.0;
    char* end = nullptr;
    const double number = std::strtod(buffer.c_str() + start, &end);
    if (end == buffer.c_str() + start)
        return 0.0; // no float prefix at all
    // A trailing "E" with no digits is not consumed as an exponent, so it reads as the exa suffix.
    double multiplier = 1.0;
    switch (*end) {
    case 'K': case 'k': multiplier = 1e3; break;
    case 'M': case 'm': multiplier = 1e6; break;
    case 'G': case 'g': multiplier = 1e9; break;
    case 'T': case 't': multiplier = 1e12; break;
    case 'P': case 'p': multiplier = 1e15; break;
    case 'E': case 'e': multiplier = 1e18; break;
    default: break;
    }
    return number * multiplier;
}

std::string format_rfc9557(int64_t epoch) {
    if (epoch <= 0)
        return "";
    const std::time_t t = static_cast<std::time_t>(epoch);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buffer[40];
    // RFC 9557 (IXDTF): RFC 3339 UTC timestamp + IANA time-zone annotation.
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ[UTC]", &tm);
    return std::string(buffer);
}

std::string suffix_string(double value, int significant_digits) {
    constexpr double kilo = 1e3, mega = 1e6, giga = 1e9, tera = 1e12, peta = 1e15, exa = 1e18;
    std::string suffix;
    double scaled = 0.0;
    bool decimal = true;

    if (value >= exa) {
        value /= peta;
        scaled = value / kilo;
        suffix = "E";
    } else if (value >= peta) {
        value /= tera;
        scaled = value / kilo;
        suffix = "P";
    } else if (value >= tera) {
        value /= giga;
        scaled = value / kilo;
        suffix = "T";
    } else if (value >= giga) {
        value /= mega;
        scaled = value / kilo;
        suffix = "G";
    } else if (value >= mega) {
        value /= kilo;
        scaled = value / kilo;
        suffix = "M";
    } else if (value >= kilo) {
        scaled = value / kilo;
        suffix = "K";
    } else {
        scaled = value;
        decimal = false;
    }

    if (significant_digits == 0) {
        if (decimal)
            return std::format("{:.3g}{}", scaled, suffix);
        return std::format("{}{}", static_cast<unsigned>(scaled), suffix);
    }
    const int decimal_places =
        significant_digits - 1 -
        (scaled > 0.0 ? static_cast<int>(std::floor(std::log10(scaled))) : 0);
    const int field_width = significant_digits + 1;
    const int precision = std::max(decimal_places, 0);
    return std::vformat("{:{}.{}f}{}",
                        std::make_format_args(scaled, field_width, precision, suffix));
}

glz::generic build_pool_status(const api::PoolSnapshot& snapshot) {
    const double uptime = std::max<double>(static_cast<double>(snapshot.uptime), 1e-9);

    double best_share_percent = 0.0;
    if (snapshot.network_diff && *snapshot.network_diff > 0.0)
        best_share_percent = std::round(snapshot.best_share / *snapshot.network_diff * 1e8) / 1e6;

    glz::generic pool_stat = glz::generic::object_t{};
    pool_stat["runtime"] = static_cast<double>(static_cast<int64_t>(uptime));
    pool_stat["lastupdate"] = format_rfc9557(snapshot.starttime + snapshot.uptime);
    pool_stat["users"] = static_cast<double>(snapshot.users);
    pool_stat["workers"] = static_cast<double>(snapshot.connected);
    pool_stat["blocks_found"] = static_cast<double>(snapshot.blocks_found);
    pool_stat["last_block_found"] = format_rfc9557(snapshot.last_block_found);

    glz::generic blocks = glz::generic::object_t{};
    for (const auto& [addr, count] : snapshot.blocks_by_address)
        blocks[addr] = static_cast<double>(count);

    glz::generic shares = glz::generic::object_t{};
    // Decimal-valued fields retain ".0" when integral; counts remain integers.
    shares["best_share_percent"] = format_json_number(best_share_percent);
    shares["accepted"] = snapshot.accepted_diff;
    shares["rejected"] = static_cast<double>(static_cast<int64_t>(snapshot.shares_rejected));
    shares["bestshare"] = snapshot.best_share;
    for (std::size_t i = 0; i < kSpsWindows.size(); ++i)
        shares[std::string("shares_per_second_") + kSpsLabels[i]] =
            format_json_number(round5(snapshot.sps_windows[i]));

    glz::generic status = glz::generic::object_t{};
    status["pool_stat"] = std::move(pool_stat);
    status["blocks_by_address"] = std::move(blocks);
    status["hashrate"] = hashrate_fields(snapshot.hashrate_windows);
    status["shares"] = std::move(shares);
    return status;
}

glz::generic build_user_stats_from(const std::string& address,
                                   const std::vector<const api::WorkerSnapshot*>& workers,
                                   size_t active_workers, const api::PoolSnapshot& snapshot) {
    const int64_t wall_now = snapshot.starttime + snapshot.uptime;
    const auto age = [wall_now](int64_t ts) -> int64_t {
        return ts > 0 ? std::max<int64_t>(0, wall_now - ts) : 0;
    };
    std::array<double, kHashrateWindows.size()> user_windows{};
    uint64_t total_shares = 0;
    uint64_t total_rejected = 0;
    double best_difficulty = 0.0;
    int64_t last_share_timestamp = 0;

    std::vector<const api::WorkerSnapshot*> ordered(workers.begin(), workers.end());
    std::ranges::sort(ordered, {}, [](const api::WorkerSnapshot* entry) { return entry->worker; });

    glz::generic worker_rows = glz::generic::array_t{};
    for (const auto* worker_ptr : ordered) {
        const auto& entry = *worker_ptr;
        for (std::size_t i = 0; i < user_windows.size(); ++i)
            user_windows[i] += entry.hashrate_windows[i];
        total_shares += entry.shares_accepted;
        total_rejected += entry.shares_rejected;
        best_difficulty = std::max(best_difficulty, entry.best_difficulty);
        last_share_timestamp = std::max(last_share_timestamp, entry.last_share_ts);

        glz::generic row = glz::generic::object_t{};
        row["workername"] = entry.worker.empty() ? address : entry.worker;
        // Merge the hashrate fields after "workername" (preserving the historical key order).
        glz::generic hashrate = hashrate_fields(entry.hashrate_windows);
        for (const auto& [key, child] : hashrate.get_object())
            row[key] = child;
        row["shares_accepted"] = static_cast<double>(entry.shares_accepted);
        row["shares_rejected"] = static_cast<double>(entry.shares_rejected);
        row["bestshare"] = format_json_number(entry.best_difficulty);
        row["lastshare"] = format_rfc9557(entry.last_share_ts);
        row["last_share_age"] = static_cast<double>(age(entry.last_share_ts));
        worker_rows.get_array().push_back(std::move(row));
    }

    glz::generic out = hashrate_fields(user_windows);
    out["lastshare"] = format_rfc9557(last_share_timestamp);
    out["last_share_age"] = static_cast<double>(age(last_share_timestamp));
    out["workers"] = static_cast<double>(active_workers);
    out["shares_accepted"] = static_cast<double>(total_shares);
    out["shares_rejected"] = static_cast<double>(total_rejected);
    out["bestshare"] = format_json_number(best_difficulty);
    const auto blocks_it = snapshot.blocks_by_address.find(address);
    out["blocks"] = static_cast<double>(
        blocks_it != snapshot.blocks_by_address.end() ? blocks_it->second : uint64_t{0});
    out["worker"] = std::move(worker_rows);
    return out;
}

glz::generic build_user_stats(const std::string& address, const api::PoolSnapshot& snapshot) {
    std::vector<const api::WorkerSnapshot*> workers;
    for (const auto& worker : snapshot.workers)
        if (worker.address == address)
            workers.push_back(&worker);
    size_t active_workers = 0;
    for (const auto& client : snapshot.clients)
        active_workers += client.address == address;
    return build_user_stats_from(address, workers, active_workers, snapshot);
}

std::optional<RecoveredStats> read_pool_status(const std::string& stats_directory) {
    const std::filesystem::path path =
        std::filesystem::path(stats_directory) / "pool" / "pool.status";
    std::ifstream stream(path, std::ios::binary);
    if (!stream)
        return std::nullopt;
    std::stringstream buffer;
    buffer << stream.rdbuf();

    try {
        const YAML::Node parsed = YAML::Load(buffer.str());
        if (!parsed.IsMap())
            return std::nullopt;
        RecoveredStats stats;
        if (const YAML::Node shares = parsed["shares"]; shares && shares.IsMap()) {
            // .as<T>(fallback) never throws, so a hand-edited file can't crash recovery.
            if (const YAML::Node accepted = shares["accepted"])
                stats.accepted_diff = accepted.as<double>(0.0);
            if (const YAML::Node best = shares["bestshare"])
                stats.best_share = best.as<double>(0.0);
        }
        if (const YAML::Node ps = parsed["pool_stat"]; ps && ps.IsMap()) {
            if (const YAML::Node bf = ps["blocks_found"])
                stats.blocks_found = bf.as<uint64_t>(uint64_t{0});
            if (const YAML::Node lb = ps["last_block_found"])
                stats.last_block_found = parse_rfc9557(lb.as<std::string>(std::string{}));
        }
        if (const YAML::Node bba = parsed["blocks_by_address"]; bba && bba.IsMap())
            for (const auto& entry : bba) {
                const auto addr = entry.first.as<std::string>(std::string{});
                if (!addr.empty())
                    stats.blocks_by_address[addr] = entry.second.as<uint64_t>(uint64_t{0});
            }
        return stats;
    } catch (const YAML::Exception&) {
        return std::nullopt;
    }
}

std::vector<RecoveredWorker> read_user_stats(const std::string& stats_directory) {
    std::vector<RecoveredWorker> out;
    const std::filesystem::path users_dir = std::filesystem::path(stats_directory) / "users";
    std::error_code ec;
    std::filesystem::directory_iterator it(users_dir, ec);
    if (ec)
        return out; // no users/ dir yet
    const auto now_wall = std::chrono::system_clock::now();
    for (; !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
        const std::filesystem::path path = it->path();
        const std::string address = path.filename().string();
        // Skip atomic_write's transient temps (.tmp.<pid>.<n>): not payout addresses, and
        // recovering one mints a phantom miner.
        if (address.find(".tmp.") != std::string::npos)
            continue;
        // File age = how long these rates have been stale.
        std::error_code mtime_ec;
        const auto mtime = std::filesystem::last_write_time(path, mtime_ec);
        double file_age = 0.0;
        if (!mtime_ec) {
            const auto sys_mtime = std::chrono::clock_cast<std::chrono::system_clock>(mtime);
            file_age = std::max(0.0, std::chrono::duration<double>(now_wall - sys_mtime).count());
        }
        std::ifstream stream(path, std::ios::binary);
        if (!stream)
            continue;
        std::stringstream buffer;
        buffer << stream.rdbuf();
        try {
            const YAML::Node parsed = YAML::Load(buffer.str());
            const YAML::Node workers = parsed["worker"];
            if (!parsed.IsMap() || !workers || !workers.IsSequence())
                continue;
            for (const auto& row : workers) {
                if (!row.IsMap())
                    continue;
                RecoveredWorker rw;
                rw.address = address;
                rw.worker = row["workername"].as<std::string>(std::string{});
                // The bare-address bucket renders its name as the address; map it back to "".
                if (rw.worker == address)
                    rw.worker.clear();
                rw.shares_accepted = row["shares_accepted"].as<uint64_t>(uint64_t{0});
                rw.shares_rejected = row["shares_rejected"].as<uint64_t>(uint64_t{0});
                rw.best_difficulty = row["bestshare"].as<double>(0.0);
                rw.last_share_ts = parse_rfc9557(row["lastshare"].as<std::string>(std::string{}));
                rw.file_age_seconds = file_age;
                for (std::size_t i = 0; i < kHashrateWindows.size(); ++i) {
                    // Files store H/s suffix strings; registry holds diff/s.
                    const double hps =
                        parse_suffix(row[std::string("hashrate") + kHashrateLabels[i]]
                                         .as<std::string>(std::string{}));
                    rw.hashrate_windows[i] = hps / kHashesPerDiff1Share;
                }
                out.push_back(std::move(rw));
            }
        } catch (const YAML::Exception&) {
            continue; // skip a malformed file, don't abort recovery
        }
    }
    return out;
}

void write_pool_status(const std::string& stats_directory, const api::PoolSnapshot& snapshot) {
    const std::string text = to_yaml(build_pool_status(snapshot));
    atomic_write(std::filesystem::path(stats_directory) / "pool" / "pool.status", text);
}

void write_user_files(const std::string& stats_directory, const api::PoolSnapshot& snapshot,
                      size_t max_user_files, double retention_seconds, double prune_sweep_seconds) {
    // One file per address, rendered from the persistent registry rows (not live sessions), so a
    // disconnected worker keeps its decaying row until retention evicts it.
    std::unordered_map<std::string, std::vector<const api::WorkerSnapshot*>> by_address;
    // Share activity (accepted + rejected) per address; rejected counts too so an all-rejecting
    // (misconfigured) rig still surfaces a file.
    std::unordered_map<std::string, uint64_t> address_shares;
    for (const auto& worker : snapshot.workers)
        if (is_safe_address(worker.address)) {
            by_address[worker.address].push_back(&worker);
            address_shares[worker.address] += worker.shares_accepted + worker.shares_rejected;
        }
    std::unordered_map<std::string, size_t> active_workers;
    for (const auto& client : snapshot.clients)
        if (client.authorized && is_safe_address(client.address))
            ++active_workers[client.address];

    struct DirRegistry {
        std::unordered_set<std::string> known;
        double last_prune = -1e18; // steady_seconds() of the last sweep
    };
    static std::unordered_map<std::string, DirRegistry> registry_by_dir;
    static double last_cap_warning = -1e18;
    const auto [registry_it, first_visit] = registry_by_dir.try_emplace(stats_directory);
    DirRegistry& registry = registry_it->second;
    const std::filesystem::path users_dir = std::filesystem::path(stats_directory) / "users";
    if (first_visit) {
        std::error_code ec;
        std::filesystem::directory_iterator it(users_dir, ec);
        if (ec && ec != std::errc::no_such_file_or_directory) {
            log::warning("Cannot read {} to seed the user-file registry ({}); retrying next cycle",
                         users_dir.string(), ec.message());
            registry_by_dir.erase(stats_directory);
            return;
        }
        ec.clear();
        for (; !ec && it != std::filesystem::directory_iterator(); it.increment(ec))
            if (const std::string name = it->path().filename().string();
                name.find(".tmp.") == std::string::npos) // ignore atomic-write temps
                registry.known.insert(name);
        if (ec) {
            log::warning("Error walking {} while seeding the user-file registry ({}); retrying "
                         "next cycle",
                         users_dir.string(), ec.message());
            registry_by_dir.erase(stats_directory);
            return;
        }
    }

    for (const auto& [address, workers] : by_address) {
        // Skip an address with no share activity: an idle rig or authorize-spam attacker mints
        // registry rows but no real stats, and writing all-zero data is just disk + ingester churn.
        if (address_shares[address] == 0)
            continue;
        if (!registry.known.contains(address)) {
            if (registry.known.size() >= max_user_files) {
                const double now = steady_seconds();
                if (now - last_cap_warning > 600.0) { // once per 10 min
                    last_cap_warning = now;
                    log::warning("users/ stats directory is at its cap ({}); not creating stats "
                                 "files for new addresses (existing ones keep updating)",
                                 max_user_files);
                }
                continue;
            }
            registry.known.insert(address);
        }
        const auto worker_entry = active_workers.find(address);
        const size_t worker_count =
            worker_entry != active_workers.end() ? worker_entry->second : 0;
        const std::string text =
            to_yaml(build_user_stats_from(address, workers, worker_count, snapshot));
        atomic_write(users_dir / address, text);
    }

    if (retention_seconds > 0 && steady_seconds() - registry.last_prune >= prune_sweep_seconds) {
        registry.last_prune = steady_seconds();
        const auto cutoff = std::filesystem::file_time_type::clock::now() -
                            std::chrono::duration_cast<std::filesystem::file_time_type::duration>(
                                std::chrono::duration<double>(retention_seconds));
        size_t pruned = 0;
        std::unordered_set<std::string> survivors;
        std::error_code ec;
        std::filesystem::directory_iterator it(users_dir, ec);
        if (!ec) {
            // increment(ec), not range-for: operator++ throws on a mid-walk error. On any walk
            // failure keep the existing registry instead of resyncing to a partial survivor set.
            for (; !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
                const auto& entry = *it;
                const std::string name = entry.path().filename().string();
                if (name.find(".tmp.") != std::string::npos)
                    continue; // in-flight atomic-write temp, not a real address
                std::error_code entry_ec;
                const auto mtime = std::filesystem::last_write_time(entry.path(), entry_ec);
                if (!by_address.contains(name) && !entry_ec && mtime < cutoff) {
                    std::filesystem::remove(entry.path(), entry_ec);
                    if (!entry_ec) {
                        ++pruned;
                        continue;
                    }
                }
                survivors.insert(name);
            }
            if (!ec)
                registry.known = std::move(survivors);
            else
                log::warning("Error walking {} during the retention sweep ({}); keeping the "
                             "registry as-is",
                             users_dir.string(), ec.message());
        }
        if (pruned > 0)
            log::info("Pruned {} stale users/ stats file(s) inactive beyond the retention window",
                      pruned);
    }
}

} // namespace erikslund::stats

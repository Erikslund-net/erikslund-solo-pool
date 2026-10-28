#pragma once
// Minimum supported Bitcoin Core release; the pool warns about older nodes at startup.
// getnetworkinfo reports CLIENT_VERSION as 10000 * major + 100 * minor + build (32.1.0 is 320100).
#include <cstdint>
#include <optional>
#include <string>

#include <glaze/glaze.hpp>

namespace erikslund::bitcoin {

inline constexpr int64_t kMinimumNodeVersion = 320'100;

// Human-readable release for a CLIENT_VERSION integer, e.g. "32.1.0".
std::string format_node_version(int64_t version);

// The integer `version` of a getnetworkinfo result, or nullopt when it is absent or malformed.
std::optional<int64_t> node_version_from_network_info(const glz::generic& network_info);

} // namespace erikslund::bitcoin

#include "bitcoin/node_version.hpp"

#include <cmath>
#include <format>

namespace erikslund::bitcoin {

namespace {
// Bitcoin Core encodes two digits each for minor and build; anything larger is not a version.
constexpr double kMaximumNodeVersion = 99'999'999.0;
} // namespace

std::string format_node_version(int64_t version) {
    return std::format("{}.{}.{}", version / 10'000, (version / 100) % 100, version % 100);
}

std::optional<int64_t> node_version_from_network_info(const glz::generic& network_info) {
    if (!network_info.is_object() || !network_info.contains("version") ||
        !network_info["version"].is_number())
        return std::nullopt;
    const double version = network_info["version"].get<double>();
    if (!std::isfinite(version) || version < 0.0 || version > kMaximumNodeVersion ||
        std::trunc(version) != version)
        return std::nullopt;
    return static_cast<int64_t>(version);
}

} // namespace erikslund::bitcoin

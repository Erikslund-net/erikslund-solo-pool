#pragma once
// Conversions between compact nBits, 256-bit target, and floating difficulty.
#include <cmath>
#include <cstdint>
#include <format>
#include <string>

#include "util/uint256.hpp"

namespace erikslund::util {

// Plain decimal for logs, never scientific notation ("20000", not "2e+04").
inline std::string format_difficulty(double difficulty) {
    if (difficulty >= 1.0) {
        if (difficulty == std::round(difficulty))
            return std::format("{:.0f}", difficulty);
        std::string text = std::format("{:.2f}", difficulty);
        text.erase(text.find_last_not_of('0') + 1);
        if (!text.empty() && text.back() == '.')
            text.pop_back();
        return text;
    }
    return std::format("{:.4g}", difficulty);
}

uint256 target_from_compact(uint32_t nbits);
uint256 target_from_difficulty(double difficulty);
double difficulty_from_target(const uint256& target);
double difficulty_from_compact(uint32_t nbits);
double maximum_difficulty_for_target(const uint256& target);
bool meets_target(const uint256& hash, const uint256& target);

} // namespace erikslund::util

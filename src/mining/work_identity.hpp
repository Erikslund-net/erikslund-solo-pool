#pragma once
// Durable startup generations and fixed-width coinbase work identifiers.

#include <cstddef>
#include <cstdint>
#include <filesystem>

namespace erikslund::mining {

inline constexpr std::size_t kWorkIdentifierSize = 2 * sizeof(uint64_t);
// PUSHDATA1 framing needs at most two additional bytes.
inline constexpr std::size_t kWorkIdentifierScriptBudget = kWorkIdentifierSize + 2;

// Must complete before issuing work; never reuse a generation after a restart.
uint64_t reserve_work_generation(const std::filesystem::path& directory);

} // namespace erikslund::mining

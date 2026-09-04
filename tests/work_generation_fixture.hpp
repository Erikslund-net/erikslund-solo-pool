#pragma once
// Unit pools use an explicit generation without touching persistent deployment state.

#include <cstdint>

namespace erikslund::test {
inline constexpr uint64_t kWorkGeneration = 1;
} // namespace erikslund::test

#pragma once
// Non-reusing counters for finite mining work spaces.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace erikslund::util {

inline uint64_t counter_maximum(std::size_t bytes) {
    if (bytes == 0 || bytes > sizeof(uint64_t))
        throw std::invalid_argument("Counter width must be between 1 and 8 bytes");
    return std::numeric_limits<uint64_t>::max() >> (8 * (sizeof(uint64_t) - bytes));
}

inline uint64_t next_counter(std::atomic<uint64_t>& counter,
                             uint64_t maximum = std::numeric_limits<uint64_t>::max()) {
    auto current = counter.load(std::memory_order_relaxed);
    do {
        if (current >= maximum)
            throw std::overflow_error("Mining work counter exhausted");
    } while (!counter.compare_exchange_weak(current, current + 1, std::memory_order_relaxed));
    return current + 1;
}

} // namespace erikslund::util

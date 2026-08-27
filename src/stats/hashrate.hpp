#pragma once
// Exponentially-decaying per-window hash/share rates: one rate per window (1m..7d),
// each share folded in with that window's time constant.
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <span>

namespace erikslund::stats {

// Monotonic clock. Durations + the decay-window clock MUST use this so a system time jump
// can't make an interval negative/huge; wall time is only for displayed/stored timestamps.
inline double steady_seconds() {
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

// Hashrate windows (seconds) and the field-name suffixes the status file uses.
inline constexpr std::array<int, 7> kHashrateWindows{60, 300, 900, 3600, 21600, 86400, 604800};
inline constexpr std::array<const char*, 7> kHashrateLabels{"1m",  "5m", "15m", "1hr",
                                                            "6hr", "1d", "7d"};
// Shares-per-second windows (a shorter set).
inline constexpr std::array<int, 4> kSpsWindows{60, 300, 900, 3600};
inline constexpr std::array<const char*, 4> kSpsLabels{"1m", "5m", "15m", "1h"};

// Expected hashes behind one difficulty-1 share (2^32). diff/s * this = H/s.
inline constexpr double kHashesPerDiff1Share = 4294967296.0;

// Fold `addend` (over `elapsed`s) into a decaying per-`interval` average; addend == 0 ages
// `value` toward zero.
inline double decay_time(double value, double addend, double elapsed, double interval) {
    if (elapsed <= 0.0)
        return value;
    const double decay = std::exp(-elapsed / interval);
    const double observed_rate = addend / elapsed;
    return value * decay + observed_rate * (1.0 - decay);
}

// Decaying rates, one per window. The owner guards add()/snapshot() with its lock.
template <std::size_t N>
class DecayingWindows {
public:
    // Seed the clock with the owner's start time so the first share folds a real interval.
    DecayingWindows(std::span<const int, N> windows, double start) : windows_(windows), last_(start) {
        rates_.fill(0.0);
    }

    void add(double addend, double now) {
        const double elapsed = now - last_;
        // Callers timestamp outside this lock, so `now` can arrive out of order; advancing last_
        // to an earlier value would corrupt every later interval.
        if (elapsed <= 0.0)
            return; // sub-tick gap or backward clock
        last_ = now;
        for (std::size_t i = 0; i < N; ++i)
            rates_[i] = decay_time(rates_[i], addend, elapsed, windows_[i]);
    }

    // Rate per window, aged to `now` (no mutation).
    std::array<double, N> snapshot(double now) const {
        std::array<double, N> out{};
        const double elapsed = now - last_;
        for (std::size_t i = 0; i < N; ++i)
            out[i] = elapsed <= 0.0 ? rates_[i] : decay_time(rates_[i], 0.0, elapsed, windows_[i]);
        return out;
    }

    // Restart recovery: adopt rates persisted `age_seconds` ago. Backdating the window clock makes
    // the next snapshot/add decay the whole downtime gap, so a restart can't resurrect them at full strength.
    void seed(const std::array<double, N>& rates, double now, double age_seconds) {
        rates_ = rates;
        last_ = now - std::max(age_seconds, 0.0);
    }

private:
    std::span<const int, N> windows_;
    std::array<double, N> rates_{};
    double last_;
};

} // namespace erikslund::stats

#include <doctest/doctest.h>

#include <array>
#include <cmath>
#include <numbers>
#include <span>
#include <string>

#include "stats/hashrate.hpp"

using namespace erikslund::stats;

TEST_CASE("decay_time returns the value unchanged for non-positive elapsed time") {
    CHECK(decay_time(5.0, 100.0, 0.0, 60.0) == doctest::Approx(5.0));
    CHECK(decay_time(5.0, 100.0, -1.0, 60.0) == doctest::Approx(5.0));
}

TEST_CASE("decay_time folds an observed rate over one time constant") {
    const double aged = decay_time(0.0, 120.0, 60.0, 60.0);
    CHECK(aged == doctest::Approx(2.0 * (1.0 - 1.0 / std::numbers::e)));
}

TEST_CASE("decay_time preserves a steady observed rate") {
    CHECK(decay_time(2.0, 120.0, 60.0, 60.0) == doctest::Approx(2.0));
}

TEST_CASE("decay_time applies one time constant of exponential decay") {
    const double aged = decay_time(10.0, 0.0, 60.0, 60.0);
    CHECK(aged == doctest::Approx(10.0 / std::numbers::e));
}

TEST_CASE("decay_time approaches zero across a huge idle gap") {
    const double aged = decay_time(10.0, 0.0, 1e9, 1.0);
    CHECK(std::isfinite(aged));
    CHECK(aged == 0.0);
}

TEST_CASE("decay_time composes across idle intervals") {
    const double aged_once = decay_time(10.0, 0.0, 120.0, 60.0);
    const double aged_twice =
        decay_time(decay_time(10.0, 0.0, 30.0, 60.0), 0.0, 90.0, 60.0);
    CHECK(aged_twice == doctest::Approx(aged_once));
}

TEST_CASE("DecayingWindows starts at zero for every window") {
    DecayingWindows<7> windows(std::span<const int, 7>(kHashrateWindows), 0.0);
    const auto snap = windows.snapshot(0.0);
    for (double rate : snap)
        CHECK(rate == doctest::Approx(0.0));
}

TEST_CASE("DecayingWindows.add ignores a non-advancing clock") {
    DecayingWindows<7> windows(std::span<const int, 7>(kHashrateWindows), 100.0);
    windows.add(1000.0, 100.0); // now == last -> no-op
    windows.add(1000.0, 50.0);  // now < last -> no-op
    const auto snap = windows.snapshot(100.0);
    for (double rate : snap)
        CHECK(rate == doctest::Approx(0.0));
}

TEST_CASE("a single add makes the short window read higher than the long window") {
    // Fold the same addend over 60s; the 1m window reacts more than the 7d window.
    DecayingWindows<7> windows(std::span<const int, 7>(kHashrateWindows), 0.0);
    windows.add(1000.0, 60.0);
    const auto snap = windows.snapshot(60.0); // snapshot at the same instant: no extra ageing
    // kHashrateWindows = {60, 300, 900, 3600, 21600, 86400, 604800}.
    CHECK(snap[0] > 0.0);
    CHECK(snap[0] > snap[1]); // 1m > 5m
    CHECK(snap[1] > snap[2]); // 5m > 15m
    CHECK(snap[6] >= 0.0);    // 7d barely moved but stays finite/non-negative
    CHECK(snap[0] > snap[6]);
}

TEST_CASE("snapshot ages the rate further as time passes without new shares") {
    DecayingWindows<7> windows(std::span<const int, 7>(kHashrateWindows), 0.0);
    windows.add(1000.0, 60.0);
    const auto at_share = windows.snapshot(60.0);
    const auto later = windows.snapshot(3600.0); // an hour later, no new shares
    CHECK(later[0] < at_share[0] * 1e-20);
    CHECK(later[0] >= 0.0);
}

TEST_CASE("snapshot does not mutate internal state (idempotent reads)") {
    DecayingWindows<7> windows(std::span<const int, 7>(kHashrateWindows), 0.0);
    windows.add(500.0, 30.0);
    const auto first = windows.snapshot(30.0);
    const auto second = windows.snapshot(30.0);
    for (size_t i = 0; i < first.size(); ++i)
        CHECK(first[i] == doctest::Approx(second[i]));
}

TEST_CASE("seed ages recovered rates across downtime") {
    DecayingWindows<7> windows(std::span<const int, 7>(kHashrateWindows), 100.0);
    std::array<double, 7> recovered_rates{};
    recovered_rates.fill(100.0);
    windows.seed(recovered_rates, 100.0, 60.0);
    CHECK(windows.snapshot(100.0)[0] == doctest::Approx(100.0 / std::numbers::e));
}

TEST_CASE("the SPS window set has the documented sizes and labels") {
    CHECK(kSpsWindows.size() == 4);
    CHECK(kSpsWindows[0] == 60);
    CHECK(kSpsWindows[3] == 3600);
    CHECK(std::string(kSpsLabels[0]) == "1m");
    CHECK(std::string(kSpsLabels[3]) == "1h");
}

#pragma once
// Stable per-worker share counters and rate state shared by authorized sessions and the registry.
#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>

#include "stats/hashrate.hpp"

namespace erikslund::stats {

struct WorkerAccountingSnapshot {
    uint64_t shares_accepted = 0;
    uint64_t shares_rejected = 0;
    double best_difficulty = 0.0;
    int64_t last_share_ts = 0;
    std::array<double, kHashrateWindows.size()> hashrate_windows{};
};

class WorkerAccounting {
public:
    explicit WorkerAccounting(double start);

    void touch(int64_t now_wall);
    void note_accepted(double credited, double share_difficulty);
    void note_rejected();

    WorkerAccountingSnapshot snapshot(double now_steady) const;
    std::pair<int64_t, int64_t> activity() const;

    void recover(uint64_t shares_accepted, uint64_t shares_rejected, double best_difficulty,
                 int64_t last_share_ts,
                 const std::array<double, kHashrateWindows.size()>& hashrate_windows,
                 double now_steady, double age_seconds);

private:
    friend struct WorkerAccountingTestPeek;

    mutable std::mutex mutex_;
    DecayingWindows<kHashrateWindows.size()> hashrate_;
    uint64_t shares_accepted_ = 0;
    uint64_t shares_rejected_ = 0;
    double best_difficulty_ = 0.0;
    int64_t last_share_ts_ = 0;
    int64_t last_activity_ts_ = 0;
};

using WorkerAccountingHandle = std::shared_ptr<WorkerAccounting>;

} // namespace erikslund::stats

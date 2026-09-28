#pragma once
// Descriptor headroom for mining admission, RPC, and local recovery work.
#include <cstdint>

namespace erikslund {
struct Config;
}

namespace erikslund::core {

struct FileBudget {
    uint64_t reserved;
    int max_clients;
};

[[nodiscard]] FileBudget file_budget(const Config& config, unsigned workers, bool file_log,
                                      uint64_t soft_limit);
void apply_file_budget(Config& config, unsigned workers, bool file_log);

} // namespace erikslund::core

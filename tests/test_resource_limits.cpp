#include <doctest/doctest.h>

#include <cstdint>
#include <limits>

#include "api/http_server.hpp"
#include "core/config.hpp"
#include "core/errors.hpp"
#include "core/resource_limits.hpp"

using namespace erikslund;

namespace {

constexpr uint64_t kUnlimitedFiles = std::numeric_limits<uint64_t>::max();
constexpr unsigned kWorkers = 4;
constexpr uint64_t kSoftLimit = 1'024;

} // namespace

TEST_CASE("file budget leaves internal headroom when miners fill every slot") {
    const Config config;
    const auto budget = core::file_budget(config, kWorkers, false, kSoftLimit);
    CHECK(budget.reserved > api::kMaxConnections);
    CHECK(budget.max_clients > 0);
    CHECK(static_cast<uint64_t>(budget.max_clients) + budget.reserved == kSoftLimit);

    const auto exact = core::file_budget(
        config, kWorkers, false, budget.reserved + static_cast<uint64_t>(config.max_clients));
    CHECK(exact.max_clients == config.max_clients);
    CHECK(exact.reserved == budget.reserved);
}

TEST_CASE("file budget preserves a smaller configured miner cap") {
    Config config;
    config.max_clients = 10;
    CHECK(core::file_budget(config, kWorkers, false, kSoftLimit).max_clients == 10);
    CHECK(core::file_budget(config, kWorkers, false, kUnlimitedFiles).max_clients == 10);
}

TEST_CASE("file budget counts resolved reactors and their concurrent spool writes") {
    const Config config;
    const auto one = core::file_budget(config, 1, false, kUnlimitedFiles);
    const auto two = core::file_budget(config, 2, false, kUnlimitedFiles);
    const auto three = core::file_budget(config, 3, false, kUnlimitedFiles);
    CHECK(two.reserved > one.reserved + 2);
    CHECK(three.reserved - two.reserved == two.reserved - one.reserved);
    CHECK_THROWS_AS(static_cast<void>(core::file_budget(config, 1'024, false, kSoftLimit)),
                    ConfigError);
    CHECK_THROWS_AS(static_cast<void>(core::file_budget(config, 0, false, kSoftLimit)),
                    ConfigError);
}

TEST_CASE("file budget counts every configured mining listener") {
    Config config;
    const auto baseline = core::file_budget(config, kWorkers, false, kUnlimitedFiles);
    config.bind_ports = {3'333, 3'335, 3'336};
    config.sv2_ports = {4'333, 4'334};
    config.sv2_plaintext_ports = {14'333};
    const auto expanded = core::file_budget(config, kWorkers, false, kUnlimitedFiles);
    CHECK(expanded.reserved == baseline.reserved + 5);
}

TEST_CASE("file budget scales RPC caches and concurrent submissions with node count") {
    Config config;
    const auto one = core::file_budget(config, kWorkers, false, kUnlimitedFiles);
    config.rpc_failover.push_back({"http://127.0.0.1:1", "", ""});
    const auto two = core::file_budget(config, kWorkers, false, kUnlimitedFiles);
    config.rpc_failover.push_back({"http://127.0.0.1:2", "", ""});
    const auto three = core::file_budget(config, kWorkers, false, kUnlimitedFiles);
    CHECK(two.reserved > one.reserved + 2);
    CHECK(three.reserved - two.reserved == two.reserved - one.reserved);
}

TEST_CASE("file budget accounts for optional IPC ZMQ and file logging") {
    Config config;
    const auto baseline = core::file_budget(config, kWorkers, false, kUnlimitedFiles);
    config.work_source = "ipc";
    const auto ipc = core::file_budget(config, kWorkers, false, kUnlimitedFiles);
    CHECK(ipc.reserved > baseline.reserved);
    config.zmq_block_endpoint = "tcp://127.0.0.1:28332";
    const auto zmq = core::file_budget(config, kWorkers, false, kUnlimitedFiles);
    CHECK(zmq.reserved > ipc.reserved);
    const auto logged = core::file_budget(config, kWorkers, true, kUnlimitedFiles);
    CHECK(logged.reserved == zmq.reserved + 1);
}

TEST_CASE("file budget fails clearly when infrastructure leaves no mining capacity") {
    Config config;
    const auto baseline = core::file_budget(config, kWorkers, false, kUnlimitedFiles);
    CHECK_THROWS_AS(static_cast<void>(core::file_budget(config, kWorkers, false, 0)), ConfigError);
    CHECK_THROWS_AS(static_cast<void>(
                        core::file_budget(config, kWorkers, false, baseline.reserved)), ConfigError);
    CHECK(core::file_budget(config, kWorkers, false, baseline.reserved + 1).max_clients == 1);

    config.max_clients = 0;
    CHECK(core::file_budget(config, kWorkers, false, baseline.reserved).max_clients == 0);
    CHECK_THROWS_AS(static_cast<void>(
                        core::file_budget(config, kWorkers, false, baseline.reserved - 1)),
                    ConfigError);
    config.max_clients = -1;
    CHECK_THROWS_AS(static_cast<void>(core::file_budget(config, kWorkers, false, kUnlimitedFiles)),
                    ConfigError);
}

TEST_CASE("file budget reclamps reloads and handles limits wider than an int") {
    Config config;
    config.max_clients = std::numeric_limits<int>::max();
    CHECK(core::file_budget(config, kWorkers, false, kUnlimitedFiles).max_clients ==
          std::numeric_limits<int>::max());
    const auto first = core::file_budget(config, kWorkers, false, kSoftLimit);
    config.max_clients = first.max_clients;
    CHECK(core::file_budget(config, kWorkers, false, kSoftLimit).max_clients == first.max_clients);
    CHECK(core::file_budget(config, kWorkers, false, kSoftLimit - 1).max_clients ==
          first.max_clients - 1);
}

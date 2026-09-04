#include <doctest/doctest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

#include "bitcoin/work_source.hpp"
#include "core/config.hpp"
#include "net/server.hpp"
#include "pool/pool.hpp"
#include "util/unique_fd.hpp"
#include "work_generation_fixture.hpp"

using namespace erikslund;
using namespace erikslund::net;

namespace erikslund::net {
struct ServerTestPeek {
    // Listener::port holds the CONFIGURED port, which is 0 here, so ask the socket for the one the
    // kernel actually assigned. Select by protocol: listeners_ also carries the SV2 ports.
    static uint16_t listener_port(const Server& server) {
        const auto listener =
            std::ranges::find_if(server.listeners_, [](const Server::Listener& value) {
                return value.protocol == WireProtocol::Sv1;
            });
        sockaddr_in address{};
        socklen_t address_size = sizeof(address);
        if (listener == server.listeners_.end() ||
            ::getsockname(listener->socket.get(), reinterpret_cast<sockaddr*>(&address),
                          &address_size) != 0)
            throw std::runtime_error("could not read test listener port");
        return ntohs(address.sin_port);
    }

    static int max_clients(const Server& server) {
        return server.max_clients_.load(std::memory_order_relaxed);
    }

    static int drop_idle_seconds(const Server& server) {
        return server.drop_idle_seconds_.load(std::memory_order_relaxed);
    }
};
} // namespace erikslund::net

namespace {

class FinalSubmitWorkSource final : public bitcoin::WorkSource {
public:
    bitcoin::ChainInfo detect_chain() override { return {.chain = "regtest", .blocks = 199}; }
    std::string get_tip() override { return {}; }
    bitcoin::BlockTemplate fetch_template() override { return {}; }
    bitcoin::HeaderFacts fetch_header(const std::string&) override { return {}; }
    std::optional<std::string> submit_block_hex(const std::string&) override { return std::nullopt; }
};

template <typename Predicate>
bool wait_until(Predicate&& predicate) {
    for (int attempt = 0; attempt < 1000; ++attempt) {
        if (predicate())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return predicate();
}

bool send_all(int fd, std::string_view data) {
    while (!data.empty()) {
        const ssize_t written = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
        if (written <= 0)
            return false;
        data.remove_prefix(static_cast<size_t>(written));
    }
    return true;
}

} // namespace

TEST_CASE("resolve_worker_count honors an explicit count and clamps auto") {
    CHECK(resolve_worker_count(4) == 4u);
    CHECK(resolve_worker_count(100) == 100u); // explicit is unclamped

    // 0 = auto: clamped so a cgroup CPU quota can't over-thread.
    const unsigned auto_count = resolve_worker_count(0);
    CHECK(auto_count >= 1u);
    CHECK(auto_count <= 16u);
}

TEST_CASE("an explicit single worker is honored") {
    CHECK(resolve_worker_count(1) == 1u);
}

TEST_CASE("Server applies reloadable connection limits") {
    Config config;
    FinalSubmitWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    Server server(pool, config);

    RuntimeConfig replacement = config.runtime_config();
    replacement.max_clients = 17;
    replacement.drop_idle_seconds = 45;
    server.reload_config(replacement);

    CHECK(ServerTestPeek::max_clients(server) == 17);
    CHECK(ServerTestPeek::drop_idle_seconds(server) == 45);
}

TEST_CASE("a negative configured count is treated as auto") {
    // configured <= 0 falls into the auto branch (clamped 1..16).
    const unsigned auto_count = resolve_worker_count(-1);
    CHECK(auto_count >= 1u);
    CHECK(auto_count <= 16u);
    // Auto is deterministic on a given host: two calls agree.
    CHECK(resolve_worker_count(-1) == resolve_worker_count(0));
}

TEST_CASE("a final submit is processed before a disconnected client is removed") {
    Config config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;
    config.worker_threads = 1;

    FinalSubmitWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    pool.detect_network();
    Server server(pool, config);
    server.start();

    const int client_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(client_fd >= 0);
    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(ServerTestPeek::listener_port(server));
    REQUIRE(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) == 1);
    REQUIRE(::connect(client_fd, reinterpret_cast<sockaddr*>(&server_address),
                      sizeof(server_address)) == 0);

    const std::string request =
        R"({"id":1,"method":"mining.subscribe","params":["test"]}
{"id":2,"method":"mining.authorize","params":["bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf.worker","x"]}
{"id":3,"method":"mining.submit","params":["worker","missing","00","00000000","00000000"]}
)";
    REQUIRE(send_all(client_fd, request));
    const linger reset_on_close{1, 0};
    REQUIRE(::setsockopt(client_fd, SOL_SOCKET, SO_LINGER, &reset_on_close,
                         sizeof(reset_on_close)) == 0);
    ::close(client_fd);

    std::jthread server_thread([&](const std::stop_token& stop) { server.run(stop); });
    CHECK(wait_until([&] { return pool.snapshot().shares_rejected == 1; }));
    CHECK(wait_until([&] { return pool.client_count() == 0; }));
    server_thread.request_stop();
    server_thread.join();
}

TEST_CASE("SV1 dispatches a limit-sized line before rejecting the next oversized line") {
    Config config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;
    config.worker_threads = 1;
    config.max_line_bytes = 128;

    FinalSubmitWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    pool.detect_network();
    Server server(pool, config);
    server.start();

    const util::UniqueFd client(::socket(AF_INET, SOCK_STREAM, 0));
    REQUIRE(client.get() >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(ServerTestPeek::listener_port(server));
    REQUIRE(::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    REQUIRE(::connect(client.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);

    std::string submit =
        R"({"id":3,"method":"mining.submit","params":["worker","missing","00","00000000","00000000"]})";
    submit.resize(config.max_line_bytes, ' ');
    std::string oversized =
        R"({"id":4,"method":"mining.submit","params":["worker","missing","00","00000000","00000000"]})";
    oversized.resize(config.max_line_bytes + 1, ' ');
    SUBCASE("completed line") { oversized += '\n'; }
    SUBCASE("unterminated line") {}
    const std::string requests =
        R"({"id":1,"method":"mining.subscribe","params":["test"]}
{"id":2,"method":"mining.authorize","params":["bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf.worker","x"]}
)" + submit + '\n' + oversized;
    REQUIRE(send_all(client.get(), requests));

    std::jthread server_thread([&](const std::stop_token& stop) { server.run(stop); });
    CHECK(wait_until([&] { return pool.snapshot().shares_rejected >= 1; }));
    CHECK(wait_until([&] { return pool.client_count() == 0; }));
    CHECK(pool.snapshot().shares_rejected == 1);
    server_thread.request_stop();
    server_thread.join();
}

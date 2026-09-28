#include <doctest/doctest.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "bitcoin/work_source.hpp"
#include "core/config.hpp"
#include "core/logging.hpp"
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

constexpr std::chrono::seconds kIoTimeout{5};
constexpr std::chrono::seconds kChildTimeout{20};
constexpr int kTestPollIntervalMs = 100;
constexpr size_t kMaxCapturedBytes = 64 * 1024;
constexpr rlim_t kExhaustionFdLimit = 128;

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

bool read_until(int fd, std::string_view expected, std::string& output) {
    const auto deadline = std::chrono::steady_clock::now() + kIoTimeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (output.contains(expected))
            return true;
        pollfd ready{fd, POLLIN, 0};
        const int result = ::poll(&ready, 1, kTestPollIntervalMs);
        if (result < 0 && errno != EINTR)
            return false;
        if (result <= 0)
            continue;
        char buffer[4096];
        const ssize_t bytes = ::read(fd, buffer, sizeof(buffer));
        if (bytes < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (bytes <= 0 || output.size() + static_cast<size_t>(bytes) > kMaxCapturedBytes)
            return false;
        output.append(buffer, static_cast<size_t>(bytes));
    }
    return output.contains(expected);
}

class StderrCapture {
public:
    StderrCapture() : saved_(::dup(STDERR_FILENO)) {
        if (!saved_)
            throw std::runtime_error("could not preserve test stderr");
        int ends[2];
        if (::pipe2(ends, O_CLOEXEC) != 0)
            throw std::runtime_error("could not create test stderr pipe");
        reader_.reset(ends[0]);
        const util::UniqueFd writer(ends[1]);
        if (::dup2(writer.get(), STDERR_FILENO) < 0)
            throw std::runtime_error("could not capture test stderr");
    }

    ~StderrCapture() { static_cast<void>(::dup2(saved_.get(), STDERR_FILENO)); }
    StderrCapture(const StderrCapture&) = delete;
    StderrCapture& operator=(const StderrCapture&) = delete;

    int fd() const { return reader_.get(); }

private:
    util::UniqueFd saved_;
    util::UniqueFd reader_;
};

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

    util::UniqueFd client(::socket(AF_INET, SOCK_STREAM, 0));
    REQUIRE(client.get() >= 0);
    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(ServerTestPeek::listener_port(server));
    REQUIRE(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) == 1);
    REQUIRE(::connect(client.get(), reinterpret_cast<sockaddr*>(&server_address),
                      sizeof(server_address)) == 0);

    std::string request =
        R"({"id":1,"method":"mining.subscribe","params":["test"]}
{"id":2,"method":"mining.authorize","params":["bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf.worker","x"]}
)";
    bool reset_client = false;
    SUBCASE("peer resets after the final submit") { reset_client = true; }
    SUBCASE("control budget is exhausted before the final submit") {
        constexpr size_t kControlRequestsToExhaustBudget = 32;
        for (size_t request_index = 0; request_index < kControlRequestsToExhaustBudget;
             ++request_index)
            request += "{\"method\":\"mining.ping\"}\n";
    }
    request +=
        R"({"id":3,"method":"mining.submit","params":["worker","missing","00","00000000","00000000"]}
)";
    // Prequeue a small batch before the reactor starts so the final submit shares its read.
    constexpr size_t kSingleReadBatchBytes = 1200;
    REQUIRE(request.size() < kSingleReadBatchBytes);
    REQUIRE(send_all(client.get(), request));
    if (reset_client) {
        const linger reset_on_close{1, 0};
        REQUIRE(::setsockopt(client.get(), SOL_SOCKET, SO_LINGER, &reset_on_close,
                             sizeof(reset_on_close)) == 0);
        client.reset();
    }

    std::jthread server_thread([&](const std::stop_token& stop) { server.run(stop); });
    CHECK(wait_until([&] { return pool.snapshot().shares_rejected == 1; }));
    // In the control-budget subcase the client stays open: the server must initiate removal.
    CHECK(wait_until([&] { return pool.client_count() == 0; }));
    server_thread.request_stop();
    server_thread.join();
}

TEST_CASE("a peer reset does not discard a submit queued behind the first read") {
    Config config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;
    config.worker_threads = 1;

    FinalSubmitWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    pool.detect_network();
    Server server(pool, config);
    server.start();

    util::UniqueFd client(::socket(AF_INET, SOCK_STREAM, 0));
    REQUIRE(client.get() >= 0);
    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(ServerTestPeek::listener_port(server));
    REQUIRE(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) == 1);
    REQUIRE(::connect(client.get(), reinterpret_cast<sockaddr*>(&server_address),
                      sizeof(server_address)) == 0);

    // Replies to the handshake fail once the peer has reset, so the write side dies during the first
    // read; the unparseable filler line keeps the submit queued for later reads.
    constexpr size_t kFillerBytes = 12 * 1024;
    std::string request =
        R"({"id":1,"method":"mining.subscribe","params":["test"]}
{"id":2,"method":"mining.authorize","params":["bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf.worker","x"]}
)";
    request.append(kFillerBytes, ' ');
    request +=
        R"(
{"id":3,"method":"mining.submit","params":["worker","missing","00","00000000","00000000"]}
)";
    REQUIRE(send_all(client.get(), request));
    const linger reset_on_close{1, 0};
    REQUIRE(::setsockopt(client.get(), SOL_SOCKET, SO_LINGER, &reset_on_close,
                         sizeof(reset_on_close)) == 0);
    client.reset();

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

TEST_CASE("acceptor descriptor exhaustion is isolated from the test runner") {
    int ends[2];
    REQUIRE(::pipe2(ends, O_CLOEXEC | O_NONBLOCK) == 0);
    util::UniqueFd output_reader(ends[0]);
    util::UniqueFd output_writer(ends[1]);
    const pid_t child = ::fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        // Only async-signal-safe calls before exec: no inherited logger or runtime locks.
        if (::dup2(output_writer.get(), STDOUT_FILENO) < 0 ||
            ::dup2(output_writer.get(), STDERR_FILENO) < 0)
            ::_exit(127);
        ::close(output_reader.get());
        ::close(output_writer.get());
        ::execl("/proc/self/exe", "erikslund_tests",
                "--test-case=acceptor descriptor exhaustion child", "--no-skip",
                "--no-colors", "--no-breaks", static_cast<char*>(nullptr));
        ::_exit(127);
    }
    output_writer.reset();
    std::string output;
    const auto drain_output = [&] {
        char buffer[4096];
        ssize_t bytes;
        while ((bytes = ::read(output_reader.get(), buffer, sizeof(buffer))) > 0) {
            const size_t keep = std::min(static_cast<size_t>(bytes),
                                        kMaxCapturedBytes - output.size());
            output.append(buffer, keep);
        }
    };
    int status = 0;
    bool timed_out = false;
    const auto deadline = std::chrono::steady_clock::now() + kChildTimeout;
    while (true) {
        drain_output();
        const pid_t completed = ::waitpid(child, &status, WNOHANG);
        if (completed == child)
            break;
        if (completed < 0 && errno != EINTR) {
            status = -1;
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            timed_out = true;
            ::kill(child, SIGKILL);
            while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {
            }
            break;
        }
        pollfd ready{output_reader.get(), POLLIN, 0};
        static_cast<void>(::poll(&ready, 1, kTestPollIntervalMs));
    }
    drain_output();
    INFO(output);
    CHECK_FALSE(timed_out);
    REQUIRE(status != -1);
    REQUIRE(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
}

// The normal test above execs only this case, keeping RLIMIT changes out of the main suite.
TEST_CASE("acceptor descriptor exhaustion child" * doctest::skip()) {
    const StderrCapture log_capture;
    const auto previous_log_level = log::level();
    log::set_level(log::Level::Warning);
    Config config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;
    config.worker_threads = 1;
    config.auth_timeout_seconds = 60;
    FinalSubmitWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    pool.detect_network();
    Server server(pool, config);
    server.start();

    const util::UniqueFd established(::socket(AF_INET, SOCK_STREAM, 0));
    const util::UniqueFd pending(::socket(AF_INET, SOCK_STREAM, 0));
    REQUIRE(established.get() >= 0);
    REQUIRE(pending.get() >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(ServerTestPeek::listener_port(server));
    REQUIRE(::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    REQUIRE(::connect(established.get(), reinterpret_cast<sockaddr*>(&address),
                      sizeof(address)) == 0);
    std::jthread server_thread([&](const std::stop_token& stop) { server.run(stop); });
    REQUIRE(send_all(established.get(),
                     "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"test\"]}\n"));
    std::string response;
    REQUIRE(read_until(established.get(), "\"id\":1", response));
    REQUIRE(pool.client_count() == 1);

    rlimit original_limit{};
    REQUIRE(::getrlimit(RLIMIT_NOFILE, &original_limit) == 0);
    const rlimit reduced_limit{std::min(original_limit.rlim_cur, kExhaustionFdLimit),
                               original_limit.rlim_max};
    REQUIRE(::setrlimit(RLIMIT_NOFILE, &reduced_limit) == 0);
    std::vector<util::UniqueFd> fillers;
    fillers.reserve(kExhaustionFdLimit);
    while (true) {
        const int fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            break;
        fillers.emplace_back(fd);
    }
    REQUIRE(errno == EMFILE);
    REQUIRE(::connect(pending.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    // TCP_DEFER_ACCEPT makes the listener readable only after the pending peer sends data.
    REQUIRE(send_all(pending.get(),
                     "{\"id\":3,\"method\":\"mining.subscribe\",\"params\":[\"test\"]}\n"));
    std::string logs;
    INFO(logs);
    REQUIRE(read_until(log_capture.fd(), "Could not accept mining client", logs));

    // An established connection must keep making progress while the acceptor lacks descriptors.
    REQUIRE(send_all(established.get(),
                     "{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[\"test\"]}\n"));
    response.clear();
    REQUIRE(read_until(established.get(), "\"id\":2", response));
    CHECK(pool.client_count() == 1);

    SUBCASE("admission recovers when descriptors become available") {
        fillers.clear();
        response.clear();
        REQUIRE(read_until(pending.get(), "\"id\":3", response));
        CHECK(pool.client_count() == 2);
    }
    SUBCASE("shutdown completes while descriptors remain exhausted") {}
    server_thread.request_stop();
    server_thread.join();
    fillers.clear();
    REQUIRE(::setrlimit(RLIMIT_NOFILE, &original_limit) == 0);
    log::set_level(previous_log_level);
}

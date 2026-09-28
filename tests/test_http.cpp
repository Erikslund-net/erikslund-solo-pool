#include <doctest/doctest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "api/http_server.hpp"
#include "bitcoin/rpc_client.hpp"
#include "bitcoin/work_source_rpc.hpp"
#include "core/config.hpp"
#include "pool/pool.hpp"
#include "work_generation_fixture.hpp"
#include "util/unique_fd.hpp"

using namespace erikslund;

namespace {

constexpr std::string_view kLoopbackAddress = "127.0.0.1";
constexpr size_t kReceiveChunkBytes = 4'096;
constexpr int kSocketTimeoutSeconds = 2;

struct WireResponse {
    int status = 0;
    std::string headers;
    std::string body;
};

struct PoolFixture {
    Config config;
    bitcoin::RpcClient rpc{"http://127.0.0.1:1", "user", "pass"};
    bitcoin::RpcWorkSource source{rpc};
    Pool pool{config, source, test::kWorkGeneration};
    api::HttpServer server{pool, std::string(kLoopbackAddress), 0};

    PoolFixture() { server.start(); }
};

[[nodiscard]] bool send_all(int socket, std::string_view bytes) {
    size_t sent = 0;
    while (sent < bytes.size()) {
        const ssize_t written =
            ::send(socket, bytes.data() + sent, bytes.size() - sent, MSG_NOSIGNAL);
        if (written <= 0)
            return false;
        sent += static_cast<size_t>(written);
    }
    return true;
}

[[nodiscard]] util::UniqueFd connect_to(uint16_t port) {
    util::UniqueFd socket{::socket(AF_INET, SOCK_STREAM, 0)};
    if (!socket)
        return {};

    timeval timeout{};
    timeout.tv_sec = kSocketTimeoutSeconds;
    if (::setsockopt(socket.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
        return {};

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (::inet_pton(AF_INET, kLoopbackAddress.data(), &address.sin_addr) != 1)
        return {};
    if (::connect(socket.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0)
        return {};
    return socket;
}

[[nodiscard]] std::optional<WireResponse> send_raw(uint16_t port, std::string_view request) {
    auto socket = connect_to(port);
    if (!socket)
        return std::nullopt;
    if (!send_all(socket.get(), request))
        return std::nullopt;

    std::string bytes;
    std::array<char, kReceiveChunkBytes> chunk{};
    while (true) {
        const ssize_t received = ::recv(socket.get(), chunk.data(), chunk.size(), 0);
        if (received > 0) {
            bytes.append(chunk.data(), static_cast<size_t>(received));
            continue;
        }
        if (received == 0)
            break;
        return std::nullopt;
    }

    const size_t first_space = bytes.find(' ');
    const size_t header_end = bytes.find("\r\n\r\n");
    if (first_space == std::string::npos || header_end == std::string::npos)
        return std::nullopt;

    WireResponse response;
    const char* status_begin = bytes.data() + first_space + 1;
    const char* status_end = status_begin + 3;
    const auto parsed = std::from_chars(status_begin, status_end, response.status);
    if (parsed.ec != std::errc{} || parsed.ptr != status_end)
        return std::nullopt;
    response.headers = bytes.substr(0, header_end + 4);
    response.body = bytes.substr(header_end + 4);
    return response;
}

[[nodiscard]] std::optional<WireResponse> request(PoolFixture& fixture, std::string_view method,
                                                   std::string_view target) {
    std::string bytes;
    bytes += method;
    bytes += ' ';
    bytes += target;
    bytes += " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    return send_raw(fixture.server.port(), bytes);
}

[[nodiscard]] bool contains(std::string_view text, std::string_view expected) {
    return text.find(expected) != std::string_view::npos;
}

} // namespace

TEST_CASE("HTTP routes preserve the pool observability API") {
    PoolFixture fixture;

    const auto root = request(fixture, "GET", "/");
    REQUIRE(root.has_value());
    CHECK(root->status == 200);
    CHECK(contains(root->headers, "Content-Type: text/html"));
    CHECK(contains(root->body, "<html"));

    const auto metrics = request(fixture, "GET", "/metrics");
    REQUIRE(metrics.has_value());
    CHECK(metrics->status == 200);
    CHECK(contains(metrics->headers, "version=0.0.4"));
    CHECK(contains(metrics->body, "erikslundpool_up"));

    for (const std::string_view path : {"/metrics.json", "/status", "/stats/pool",
                                        "/stats/stratifier", "/stats/connector",
                                        "/stats/generator"}) {
        CAPTURE(path);
        const auto response = request(fixture, "GET", path);
        REQUIRE(response.has_value());
        CHECK(response->status == 200);
        CHECK(contains(response->headers, "Content-Type: application/json"));
    }
}

TEST_CASE("HTTP health aliases remain cheap readiness probes") {
    PoolFixture fixture;

    for (const std::string_view path : {"/health", "/healthz"}) {
        CAPTURE(path);
        const auto response = request(fixture, "GET", path);
        REQUIRE(response.has_value());
        CHECK(response->status == 503);
        CHECK(response->body == "degraded\n");
    }

    const auto favicon = request(fixture, "GET", "/favicon.ico");
    REQUIRE(favicon.has_value());
    CHECK(favicon->status == 204);
    CHECK(favicon->body.empty());
}

TEST_CASE("HTTP routing delegates methods and parsing to erikslund-http-embedded") {
    PoolFixture fixture;

    const auto missing = request(fixture, "GET", "/does-not-exist");
    REQUIRE(missing.has_value());
    CHECK(missing->status == 404);

    const auto write = request(fixture, "POST", "/metrics");
    REQUIRE(write.has_value());
    CHECK(write->status == 405);
    CHECK(contains(write->headers, "Allow: GET, HEAD"));

    const auto head = request(fixture, "HEAD", "/metrics?refresh=1");
    REQUIRE(head.has_value());
    CHECK(head->status == 200);
    CHECK(head->body.empty());
    CHECK(contains(head->headers, "Content-Length:"));

    const auto malformed = send_raw(fixture.server.port(),
                                    "GET /metrics HTTP/1.1\r\nConnection: close\r\n\r\n");
    REQUIRE(malformed.has_value());
    CHECK(malformed->status == 400);
}

TEST_CASE("HTTP client statistics validate decoded addresses") {
    PoolFixture fixture;

    for (const std::string& path : {
             std::string("/stats/client/"),
             std::string("/stats/client/bad!char"),
             std::string("/stats/client/bad%21char"),
             "/stats/client/" + std::string(128, 'a'),
         }) {
        CAPTURE(path);
        const auto response = request(fixture, "GET", path);
        REQUIRE(response.has_value());
        CHECK(response->status == 400);
    }

    const auto unknown = request(fixture, "GET", "/stats/client/some.worker_name");
    REQUIRE(unknown.has_value());
    CHECK(unknown->status == 404);

    const auto maximum = request(fixture, "GET", "/stats/client/" + std::string(127, 'a'));
    REQUIRE(maximum.has_value());
    CHECK(maximum->status == 404);
}

TEST_CASE("HTTP request limits reject oversized targets before routing") {
    PoolFixture fixture;
    const auto response = request(fixture, "GET", "/" + std::string(3'000, 'a'));
    REQUIRE(response.has_value());
    CHECK(response->status == 414);
}

TEST_CASE("HTTP request bodies are rejected before routing") {
    PoolFixture fixture;
    const auto response = send_raw(
        fixture.server.port(),
        "POST /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1\r\nConnection: "
        "close\r\n\r\nx");
    REQUIRE(response.has_value());
    CHECK(response->status == 413);
}

TEST_CASE("HTTP connections are capped and service recovers when slots are released") {
    PoolFixture fixture;
    std::vector<util::UniqueFd> held;
    const auto hold_connection = [&] {
        auto socket = connect_to(fixture.server.port());
        REQUIRE(socket);
        REQUIRE(send_all(socket.get(), "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n"));
        held.push_back(std::move(socket));
    };
    for (unsigned connection = 0; connection < api::kMaxConnections - 1; ++connection)
        hold_connection();

    const auto last_slot = request(fixture, "GET", "/health");
    REQUIRE(last_slot.has_value());
    CHECK(last_slot->status == 503);
    hold_connection();
    CHECK_FALSE(request(fixture, "GET", "/health").has_value());

    held.clear();
    constexpr auto kRecoveryWait = std::chrono::seconds(2);
    constexpr auto kRetryInterval = std::chrono::milliseconds(10);
    const auto deadline = std::chrono::steady_clock::now() + kRecoveryWait;
    std::optional<WireResponse> recovered;
    do {
        recovered = request(fixture, "GET", "/health");
        if (recovered)
            break;
        std::this_thread::sleep_for(kRetryInterval);
    } while (std::chrono::steady_clock::now() < deadline);
    REQUIRE(recovered.has_value());
    CHECK(recovered->status == 503);
}

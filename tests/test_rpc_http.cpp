// RpcClient against a real loopback HTTP server, so libcurl's own request framing is exercised.
// Invariant pinned: a multi-megabyte submitblock is sent without "Expect: 100-continue". Bitcoin
// Core 32's HTTP server never answers that header, so libcurl would hold the block back a second.
#include <doctest/doctest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "bitcoin/rpc_client.hpp"

using namespace erikslund;
using namespace erikslund::bitcoin;

namespace {

constexpr int kIoTimeoutMilliseconds = 10'000;

std::string lowercase(std::string text) {
    std::ranges::transform(text, text.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

struct Request {
    std::string headers; // request line and headers, lowercased
    std::string body;
};

// Answers each request with the next canned JSON-RPC body, and never sends "100 Continue".
class LoopbackRpcServer {
public:
    explicit LoopbackRpcServer(std::vector<std::string> replies)
        : listener_(::socket(AF_INET, SOCK_STREAM, 0)) {
        REQUIRE(listener_ >= 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(::bind(listener_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        REQUIRE(::listen(listener_, 4) == 0);
        socklen_t length = sizeof(address);
        REQUIRE(::getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &length) == 0);
        port_ = ntohs(address.sin_port);
        server_ = std::thread([this, replies = std::move(replies)] { serve(replies); });
    }

    LoopbackRpcServer(const LoopbackRpcServer&) = delete;
    LoopbackRpcServer& operator=(const LoopbackRpcServer&) = delete;

    ~LoopbackRpcServer() {
        if (server_.joinable())
            server_.join();
        ::close(listener_);
    }

    std::string url() const { return "http://127.0.0.1:" + std::to_string(port_); }

    // Waits for every scripted request to be answered.
    std::vector<Request> requests() {
        server_.join();
        return std::move(requests_);
    }

private:
    static bool readable(int fd) {
        pollfd event{fd, POLLIN, 0};
        return ::poll(&event, 1, kIoTimeoutMilliseconds) == 1;
    }

    static bool read_some(int fd, std::string& buffer) {
        constexpr std::size_t kChunk = 64 * 1024;
        if (!readable(fd))
            return false;
        const std::size_t used = buffer.size();
        buffer.resize(used + kChunk);
        const ssize_t received = ::recv(fd, buffer.data() + used, kChunk, 0);
        buffer.resize(used + static_cast<std::size_t>(std::max<ssize_t>(received, 0)));
        return received > 0;
    }

    static bool read_request(int fd, std::string& pending, Request& request) {
        std::size_t header_end = std::string::npos;
        while ((header_end = pending.find("\r\n\r\n")) == std::string::npos)
            if (!read_some(fd, pending))
                return false;
        request.headers = lowercase(pending.substr(0, header_end + 2));
        const auto length_at = request.headers.find("content-length:");
        if (length_at == std::string::npos)
            return false;
        const std::size_t body_length =
            std::stoul(request.headers.substr(length_at + std::string_view("content-length:").size()));
        const std::size_t body_start = header_end + 4;
        while (pending.size() - body_start < body_length)
            if (!read_some(fd, pending))
                return false;
        request.body = pending.substr(body_start, body_length);
        pending.erase(0, body_start + body_length);
        return true;
    }

    static void reply(int fd, const std::string& body) {
        const std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                     "Content-Length: " +
                                     std::to_string(body.size()) + "\r\n\r\n" + body;
        std::size_t sent = 0;
        while (sent < response.size()) {
            const ssize_t written =
                ::send(fd, response.data() + sent, response.size() - sent, MSG_NOSIGNAL);
            if (written <= 0)
                return;
            sent += static_cast<std::size_t>(written);
        }
    }

    // libcurl may open a fresh connection per worker thread, so accept until every reply is used.
    void serve(const std::vector<std::string>& replies) {
        std::size_t next = 0;
        while (next < replies.size() && readable(listener_)) {
            const int connection = ::accept(listener_, nullptr, nullptr);
            if (connection < 0)
                return;
            std::string pending;
            Request request;
            while (next < replies.size() && read_request(connection, pending, request)) {
                requests_.push_back(request);
                reply(connection, replies[next++]);
            }
            ::close(connection);
        }
    }

    int listener_;
    unsigned short port_ = 0;
    std::thread server_;
    std::vector<Request> requests_;
};

} // namespace

TEST_CASE("a multi-megabyte submitblock does not ask the node for 100 Continue") {
    LoopbackRpcServer server({R"({"result":null,"error":null,"id":1})"});
    RpcClient rpc(server.url(), "user", "pass", /*timeout_seconds=*/5);
    const std::string block_hex(2 * 1024 * 1024, '0');

    CHECK_FALSE(rpc.submitblock(block_hex).has_value());
    const auto requests = server.requests();
    REQUIRE(requests.size() == 1);
    CHECK(requests[0].headers.find("expect:") == std::string::npos);
    CHECK(requests[0].body.find(block_hex) != std::string::npos);
}

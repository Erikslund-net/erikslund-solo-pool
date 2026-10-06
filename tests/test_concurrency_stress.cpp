// Stress cork/send/flush interleavings without exceeding the outbound buffer limit.
#include <doctest/doctest.h>

#include <sys/socket.h>
#include <unistd.h>

#include <barrier>
#include <cstddef>
#include <format>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>

#include "net/socket_connection.hpp"

using namespace erikslund::net;

namespace {

constexpr int kLinesPerSender = 4000;
constexpr int kLinesPerBatch = 1000;
constexpr int kSenderCount = 3;
constexpr size_t kMaximumBatchBytes = size_t{48} * 1024;
static_assert(kLinesPerSender % kLinesPerBatch == 0);

size_t wire_bytes(std::string_view prefix) {
    size_t total = 0;
    for (int line_index = 0; line_index < kLinesPerSender; ++line_index)
        total += prefix.size() + 1 + std::format("{}", line_index).size() + 1;
    return total;
}

} // namespace

TEST_CASE("cork/send/flush are race-free and line-atomic across reactor and work threads") {
    const size_t longest_line_bytes = std::format("notify-{}\n", kLinesPerSender - 1).size();
    REQUIRE(longest_line_bytes * kLinesPerBatch * kSenderCount < kMaximumBatchBytes);

    int sv[2];
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    // Blocking sends drain each batch; the barrier bounds queues even if a cork window pauses.

    std::string received;
    const size_t expected_bytes = wire_bytes("ack") + wire_bytes("notify") + wire_bytes("burst");

    std::jthread reader([&] {
        char buf[8192];
        ssize_t n;
        while ((n = ::recv(sv[1], buf, sizeof(buf), 0)) > 0)
            received.append(buf, static_cast<size_t>(n));
    });

    bool connection_dead = false;
    {
        SocketConnection conn(sv[0], 30.0, "test:stress"); // owns sv[0]
        std::barrier batch_finished(kSenderCount);

        std::jthread reactor([&] {
            for (int line_index = 0; line_index < kLinesPerSender; ++line_index) {
                conn.cork();
                conn.send_line(std::format("ack-{}", line_index));
                conn.uncork();
                if ((line_index + 1) % kLinesPerBatch == 0)
                    batch_finished.arrive_and_wait();
            }
        });
        std::jthread work([&] {
            for (int line_index = 0; line_index < kLinesPerSender; ++line_index) {
                conn.send_line(std::format("notify-{}", line_index));
                if ((line_index + 1) % kLinesPerBatch == 0)
                    batch_finished.arrive_and_wait();
            }
        });
        std::jthread burst([&] {
            for (int line_index = 0; line_index < kLinesPerSender; ++line_index) {
                conn.send_line(std::format("burst-{}", line_index));
                if ((line_index + 1) % kLinesPerBatch == 0)
                    batch_finished.arrive_and_wait();
            }
        });
        std::jthread flusher([&](const std::stop_token& stop) {
            while (!stop.stop_requested()) {
                conn.flush_outbox();
                std::this_thread::yield();
            }
        });

        reactor.join();
        work.join();
        burst.join();
        flusher.request_stop();
        flusher.join();

        connection_dead = conn.dead();
    } // ~SocketConnection closes sv[0] -> reader sees EOF
    reader.join();
    ::close(sv[1]);
    REQUIRE_FALSE(connection_dead);
    REQUIRE(received.size() == expected_bytes);

    // Every received line must be exactly one sent line (atomic framing, no interleaved bytes),
    // each sender's sequence must arrive in FIFO order, and nothing may be lost or duplicated.
    int next_expected[3] = {0, 0, 0}; // ack, notify, burst
    const std::string prefixes[3] = {"ack-", "notify-", "burst-"};
    size_t start = 0;
    size_t lines = 0;
    while (start < received.size()) {
        const size_t newline = received.find('\n', start);
        REQUIRE(newline != std::string::npos); // no torn trailing fragment
        const std::string_view line = std::string_view(received).substr(start, newline - start);
        start = newline + 1;
        ++lines;
        bool matched = false;
        for (int sender = 0; sender < 3; ++sender) {
            if (!line.starts_with(prefixes[sender]))
                continue;
            const std::string expected =
                prefixes[sender] + std::format("{}", next_expected[sender]);
            REQUIRE(line == expected); // FIFO per sender, no gaps, no duplicates
            ++next_expected[sender];
            matched = true;
            break;
        }
        REQUIRE(matched); // no corrupted / interleaved line
    }
    CHECK(lines == static_cast<size_t>(3 * kLinesPerSender));
    CHECK(next_expected[0] == kLinesPerSender);
    CHECK(next_expected[1] == kLinesPerSender);
    CHECK(next_expected[2] == kLinesPerSender);
}

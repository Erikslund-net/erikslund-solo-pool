#include <doctest/doctest.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

#include "net/socket_connection.hpp"

using namespace erikslund::net;

namespace {
int getopt_int(int fd, int level, int option) {
    int value = 0;
    socklen_t len = sizeof(value);
    ::getsockopt(fd, level, option, &value, &len);
    return value;
}

void set_nonblocking(int fd) { ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK); }

// A connected non-blocking AF_UNIX stream pair with small kernel buffers so writes back up
// quickly. sv[0] is handed to the SocketConnection (closed by its dtor); the test owns sv[1].
void make_pair(int sv[2], int bufbytes = 2048) {
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    ::setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &bufbytes, sizeof(bufbytes));
    ::setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &bufbytes, sizeof(bufbytes));
    set_nonblocking(sv[0]);
}

size_t drain_peer(int fd) {
    size_t total = 0;
    char buf[4096];
    ssize_t n;
    while ((n = ::recv(fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0)
        total += static_cast<size_t>(n);
    return total;
}
} // namespace

TEST_CASE("tune_socket sets no-Nagle + keepalive on an accepted fd") {
    // These options are settable on an unconnected TCP socket, so no peer needed.
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    tune_socket(fd, /*work_rebroadcast_seconds=*/30.0);

    CHECK(getopt_int(fd, IPPROTO_TCP, TCP_NODELAY) == 1);
    CHECK(getopt_int(fd, SOL_SOCKET, SO_KEEPALIVE) == 1);
    CHECK(getopt_int(fd, IPPROTO_TCP, TCP_KEEPIDLE) == 60);
    CHECK(getopt_int(fd, IPPROTO_TCP, TCP_KEEPINTVL) == 20);
    CHECK(getopt_int(fd, IPPROTO_TCP, TCP_KEEPCNT) == 5);
#ifdef TCP_USER_TIMEOUT
    CHECK(getopt_int(fd, IPPROTO_TCP, TCP_USER_TIMEOUT) == (60 + 20 * 5) * 1000);
#endif
    ::close(fd);
}

TEST_CASE("keepalive_user_timeout_ms floors at the keepalive window, else 2x rebroadcast") {
    CHECK(keepalive_user_timeout_ms(30) == (60 + 20 * 5) * 1000); // small push: window floor wins
    CHECK(keepalive_user_timeout_ms(0) == (60 + 20 * 5) * 1000);  // floor
    CHECK(keepalive_user_timeout_ms(600) == 600 * 2 * 1000);      // large push: 2x the interval
}

TEST_CASE("keepalive_user_timeout_ms crossover at the window/2 point") {
    // The window is 60 + 20*5 = 160s. 2x rebroadcast overtakes the floor at 80s.
    constexpr int window_ms = (60 + 20 * 5) * 1000;
    CHECK(keepalive_user_timeout_ms(79) == window_ms);    // 2x79 = 158 < 160 -> floor
    CHECK(keepalive_user_timeout_ms(80) == window_ms);    // 2x80 = 160 == floor (max picks either)
    CHECK(keepalive_user_timeout_ms(81) == 81 * 2 * 1000); // 2x81 = 162 > 160 -> 2x wins
    CHECK(keepalive_user_timeout_ms(120) == 120 * 2 * 1000);
}

TEST_CASE("keepalive_user_timeout_ms ignores a negative rebroadcast (floor wins)") {
    constexpr int window_ms = (60 + 20 * 5) * 1000;
    CHECK(keepalive_user_timeout_ms(-100) == window_ms);
}

TEST_CASE("tune_socket scales TCP_USER_TIMEOUT with a large rebroadcast interval") {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    tune_socket(fd, /*work_rebroadcast_seconds=*/300.0);
    // Core options are still set.
    CHECK(getopt_int(fd, IPPROTO_TCP, TCP_NODELAY) == 1);
    CHECK(getopt_int(fd, SOL_SOCKET, SO_KEEPALIVE) == 1);
#ifdef TCP_USER_TIMEOUT
    // 2 * 300 = 600s > 160s floor -> 600000 ms.
    CHECK(getopt_int(fd, IPPROTO_TCP, TCP_USER_TIMEOUT) == 600 * 1000);
#endif
    ::close(fd);
}

TEST_CASE("keepalive_user_timeout_ms saturates before integer overflow") {
    constexpr int kMaximum = std::numeric_limits<int>::max();
    CHECK(keepalive_user_timeout_ms(1000000) == 2000000000);
    CHECK(keepalive_user_timeout_ms(static_cast<double>(kMaximum) / 2000.0) == kMaximum);
    CHECK(keepalive_user_timeout_ms(2000000) == kMaximum);
    CHECK(keepalive_user_timeout_ms(std::numeric_limits<double>::max()) == kMaximum);

    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    tune_socket(fd, std::numeric_limits<double>::max());
#ifdef TCP_USER_TIMEOUT
    CHECK(getopt_int(fd, IPPROTO_TCP, TCP_USER_TIMEOUT) == kMaximum);
#endif
    ::close(fd);
}

TEST_CASE("send_line frames the line and delivers it on a writable socket") {
    int sv[2];
    make_pair(sv);
    {
        SocketConnection conn(sv[0], 30.0, "test:1"); // owns sv[0]
        conn.send_line("hello");
        CHECK_FALSE(conn.dead());
        char buf[16] = {};
        const ssize_t n = ::recv(sv[1], buf, sizeof(buf), 0);
        REQUIRE(n == 6);
        CHECK(std::string(buf, 6) == "hello\n");
    }
    ::close(sv[1]);
}

TEST_CASE("send_lines coalesces several lines into one framed flight") {
    int sv[2];
    make_pair(sv);
    {
        SocketConnection conn(sv[0], 30.0, "test:lines"); // owns sv[0]
        const std::array<std::string_view, 2> flight{"alpha", "beta"};
        conn.send_lines(flight);
        CHECK_FALSE(conn.dead());
        // Both lines arrive newline-framed, in order, from a single coalesced write.
        char buf[32] = {};
        const ssize_t n = ::recv(sv[1], buf, sizeof(buf), 0);
        REQUIRE(n == 11);
        CHECK(std::string(buf, 11) == "alpha\nbeta\n");
    }
    ::close(sv[1]);
}

TEST_CASE("send_bytes preserves binary framing without adding a delimiter") {
    int sv[2];
    make_pair(sv);
    {
        SocketConnection conn(sv[0], 30.0, "test:bytes");
        const std::array<uint8_t, 5> payload{0x00, 0x0a, 0xff, 0x01, 0x00};
        conn.send_bytes(erikslund::ByteView(payload));
        char buffer[8] = {};
        const ssize_t size = ::recv(sv[1], buffer, sizeof(buffer), 0);
        REQUIRE(size == static_cast<ssize_t>(payload.size()));
        CHECK(std::equal(payload.begin(), payload.end(),
                         reinterpret_cast<const uint8_t*>(buffer)));
    }
    ::close(sv[1]);
}

TEST_CASE("cork defers the syscall; uncork delivers everything in one flight") {
    int sv[2];
    make_pair(sv);
    {
        SocketConnection conn(sv[0], 30.0, "test:cork");
        conn.cork();
        conn.send_line("one");
        conn.send_line("two");
        // Nothing on the wire while corked -- the sends only queued.
        char buf[32] = {};
        CHECK(::recv(sv[1], buf, sizeof(buf), MSG_DONTWAIT) < 0);
        conn.uncork();
        CHECK_FALSE(conn.dead());
        const ssize_t n = ::recv(sv[1], buf, sizeof(buf), 0);
        REQUIRE(n == 8);
        CHECK(std::string(buf, 8) == "one\ntwo\n"); // framed, ordered, single flight
    }
    ::close(sv[1]);
}

TEST_CASE("a work-thread send during a cork window is queued and flushed by uncork") {
    int sv[2];
    make_pair(sv);
    {
        SocketConnection conn(sv[0], 30.0, "test:cork-notify");
        conn.cork();
        conn.send_line("ack");
        conn.send_line("notify"); // e.g. a broadcast landing mid-chunk: deferred, not lost
        conn.uncork();
        char buf[32] = {};
        const ssize_t n = ::recv(sv[1], buf, sizeof(buf), 0);
        REQUIRE(n == 11);
        CHECK(std::string(buf, 11) == "ack\nnotify\n");
        // After uncork the connection is back to direct sends.
        conn.send_line("direct");
        const ssize_t m = ::recv(sv[1], buf, sizeof(buf), 0);
        REQUIRE(m == 7);
        CHECK(std::string(buf, 7) == "direct\n");
    }
    ::close(sv[1]);
}

TEST_CASE("the outbox cap still fails a flooded connection while corked") {
    int sv[2];
    make_pair(sv);
    {
        SocketConnection conn(sv[0], 30.0, "test:cork-cap");
        conn.cork();
        // While corked nothing drains, so the cap is the only defense; it must still fire.
        const std::string chunk(2000, 'z');
        for (int i = 0; i < 40 && !conn.dead(); ++i)
            conn.send_line(chunk);
        CHECK(conn.dead());
        conn.uncork(); // must be safe (idempotent no-op) on a dead connection
        CHECK(conn.dead());
    }
    ::close(sv[1]);
}

TEST_CASE("send_line never blocks and drops a peer that won't drain past the outbox cap") {
    int sv[2];
    make_pair(sv);
    {
        SocketConnection conn(sv[0], 30.0, "test:2");
        // Never read sv[1]: the socket fills, then the outbox does. Far more than the 64 KB cap;
        // if this test returns at all, send_line did not block.
        const std::string chunk(2000, 'x');
        for (int i = 0; i < 100 && !conn.dead(); ++i)
            conn.send_line(chunk);
        CHECK(conn.dead()); // overflowed -> marked dead + shutdown
        // A dead connection ignores further sends without blocking or growing memory.
        conn.send_line("ignored");
        CHECK(conn.dead());
    }
    ::close(sv[1]);
}

TEST_CASE("detach_reactor makes the connection inert (no further sends, no epoll touch)") {
    int sv[2];
    make_pair(sv);
    {
        SocketConnection conn(sv[0], 30.0, "test:4");
        conn.detach_reactor();
        CHECK(conn.dead());
        conn.send_line("nope"); // dead -> dropped, must not reach the peer
        char buf[16];
        CHECK(::recv(sv[1], buf, sizeof(buf), MSG_DONTWAIT) < 0); // nothing delivered
        CHECK_FALSE(conn.flush_outbox());                          // dead -> false
    }
    ::close(sv[1]);
}

TEST_CASE("flush_outbox drains the backlog once the peer starts reading again") {
    int sv[2];
    make_pair(sv);
    {
        SocketConnection conn(sv[0], 30.0, "test:3");
        // Queue several KB while the peer is silent -- some sent, the rest buffered, not yet dead.
        const std::string chunk(2000, 'y');
        for (int i = 0; i < 12; ++i)
            conn.send_line(chunk);
        REQUIRE_FALSE(conn.dead());
        // Now the peer reads; flushing should push the backlog out across a few rounds.
        size_t received = 0;
        for (int round = 0; round < 100; ++round) {
            received += drain_peer(sv[1]);
            REQUIRE(conn.flush_outbox()); // stays alive while draining
        }
        received += drain_peer(sv[1]);
        // A sentinel after the backlog confirms ordering survived and the queue is moving.
        conn.send_line("sentinel");
        for (int round = 0; round < 10; ++round) {
            received += drain_peer(sv[1]);
            conn.flush_outbox();
        }
        CHECK_FALSE(conn.dead());
        CHECK(received >= 12 * 2001); // all framed chunks (2000 + '\n') made it through
    }
    ::close(sv[1]);
}

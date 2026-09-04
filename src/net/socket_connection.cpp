#include "net/socket_connection.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <span>
#include <utility>

namespace erikslund::net {

namespace {

constexpr int kKeepaliveIdleSeconds = 60;
constexpr int kKeepaliveIntervalSeconds = 20;
constexpr int kKeepaliveProbeCount = 5;

constexpr std::size_t kMaxOutboxBytes = std::size_t{64} * 1024;

} // namespace

std::string describe_peer(const sockaddr_storage& peer_address) {
    char host[INET6_ADDRSTRLEN] = {};
    uint16_t port = 0;
    if (peer_address.ss_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&peer_address);
        inet_ntop(AF_INET, &ipv4->sin_addr, host, sizeof(host));
        port = ntohs(ipv4->sin_port);
    } else if (peer_address.ss_family == AF_INET6) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(&peer_address);
        inet_ntop(AF_INET6, &ipv6->sin6_addr, host, sizeof(host));
        port = ntohs(ipv6->sin6_port);
    } else {
        return "unknown";
    }
    return std::string(host) + ":" + std::to_string(port);
}

int keepalive_user_timeout_ms(double work_rebroadcast_seconds) {
    constexpr int kMaximumTimeout = std::numeric_limits<int>::max();
    if (work_rebroadcast_seconds >= static_cast<double>(kMaximumTimeout) / 2000.0)
        return kMaximumTimeout;
    const int window = kKeepaliveIdleSeconds + kKeepaliveIntervalSeconds * kKeepaliveProbeCount;
    const double seconds = std::max(static_cast<double>(window), 2.0 * work_rebroadcast_seconds);
    return static_cast<int>(seconds * 1000.0);
}

void tune_socket(int fd, double work_rebroadcast_seconds) {
    const int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    ::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    const int idle = kKeepaliveIdleSeconds;
    const int interval = kKeepaliveIntervalSeconds;
    const int count = kKeepaliveProbeCount;
    ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
    ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
#ifdef TCP_USER_TIMEOUT
    const int user_timeout = keepalive_user_timeout_ms(work_rebroadcast_seconds);
    ::setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout, sizeof(user_timeout));
#endif
}

SocketConnection::SocketConnection(int fd, double work_rebroadcast_seconds, std::string peer)
    : fd_(fd), peer_(std::move(peer)) {
    tune_socket(fd, work_rebroadcast_seconds);
}

SocketConnection::~SocketConnection() {
    if (fd_ >= 0)
        ::close(fd_);
}

void SocketConnection::attach_reactor(int epoll_fd, void* epoll_data) {
    const std::scoped_lock lock(write_mutex_);
    epoll_fd_ = epoll_fd;
    epoll_data_ = epoll_data;
}

void SocketConnection::detach_reactor() {
    const std::scoped_lock lock(write_mutex_);
    dead_.store(true, std::memory_order_relaxed);
    epoll_fd_ = -1;       // arm_write_interest_locked now short-circuits
    epoll_data_ = nullptr;
}

void SocketConnection::send_line(std::string_view line) {
    send_lines(std::span<const std::string_view>(&line, 1));
}

void SocketConnection::send_lines(std::span<const std::string_view> lines) {
    const std::scoped_lock lock(write_mutex_);
    if (dead_.load(std::memory_order_relaxed))
        return;
    if (outbox_pos_ > 0) {
        outbox_.erase(0, outbox_pos_);
        outbox_pos_ = 0;
    }
    for (std::string_view line : lines) {
        outbox_.append(line);
        outbox_.push_back('\n');
    }
    flush_after_enqueue_locked();
}

void SocketConnection::send_bytes(ByteView bytes) {
    const std::scoped_lock lock(write_mutex_);
    if (dead_.load(std::memory_order_relaxed))
        return;
    if (outbox_pos_ > 0) {
        outbox_.erase(0, outbox_pos_);
        outbox_pos_ = 0;
    }
    outbox_.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    flush_after_enqueue_locked();
}

void SocketConnection::flush_after_enqueue_locked() {
    if (outbox_.size() > kMaxOutboxBytes) {
        fail_locked(); // peer cannot keep up; drop it rather than buffer unboundedly
        return;
    }
    if (corked_)
        return;
    if (!drain_locked()) {
        fail_locked();
        return;
    }
    arm_write_interest_locked(outbox_pos_ < outbox_.size());
}

void SocketConnection::cork() {
    const std::scoped_lock lock(write_mutex_);
    corked_ = true;
}

void SocketConnection::uncork() {
    const std::scoped_lock lock(write_mutex_);
    corked_ = false;
    if (dead_.load(std::memory_order_relaxed))
        return;
    if (!drain_locked()) {
        fail_locked();
        return;
    }
    arm_write_interest_locked(outbox_pos_ < outbox_.size());
}

bool SocketConnection::flush_outbox() {
    const std::scoped_lock lock(write_mutex_);
    if (dead_.load(std::memory_order_relaxed))
        return false;
    if (!drain_locked()) {
        fail_locked();
        return false;
    }
    arm_write_interest_locked(outbox_pos_ < outbox_.size());
    return true;
}

bool SocketConnection::drain_locked() {
    while (outbox_pos_ < outbox_.size()) {
        const ssize_t n =
            ::send(fd_, outbox_.data() + outbox_pos_, outbox_.size() - outbox_pos_, MSG_NOSIGNAL);
        if (n > 0) {
            outbox_pos_ += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break; // socket full; the remainder stays queued for EPOLLOUT
        return false; // hard error (EPIPE / ECONNRESET / ...)
    }
    if (outbox_pos_ == outbox_.size()) { // fully drained -> release buffer
        outbox_.clear();
        outbox_pos_ = 0;
    }
    return true;
}

void SocketConnection::arm_write_interest_locked(bool want_write) {
    if (epoll_fd_ < 0 || want_write == epollout_armed_)
        return;
    epoll_event event{};
    event.events = want_write ? (EPOLLIN | EPOLLOUT) : EPOLLIN;
    event.data.ptr = epoll_data_;
    ::epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd_, &event);
    epollout_armed_ = want_write;
}

void SocketConnection::fail_locked() {
    dead_.store(true, std::memory_order_relaxed);
    outbox_.clear();
    outbox_pos_ = 0;
    ::shutdown(fd_, SHUT_RDWR);
}

} // namespace erikslund::net

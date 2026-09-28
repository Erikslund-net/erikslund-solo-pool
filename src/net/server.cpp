#include "net/server.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <deque>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "core/logging.hpp"
#include "net/proxy_protocol.hpp"
#include "net/socket_connection.hpp"
#include "sv2/noise_connection.hpp"
#include "sv2/session.hpp"
#include "util/endian.hpp"
#include "util/unique_fd.hpp"

namespace erikslund::net {

struct IncomingConnection {
    int fd;
    std::string peer;
    WireProtocol protocol;
};

struct ClientConnection {
    int fd;
    WireProtocol protocol;
    std::shared_ptr<SocketConnection> socket;
    std::shared_ptr<mining::Client> session;
    std::shared_ptr<stratum::Session> sv1_session;
    std::shared_ptr<sv2::Session> sv2_session;
    std::shared_ptr<sv2::NoiseConnection> noise_connection;
    std::string buffer;
    std::chrono::steady_clock::time_point last_activity;
    std::chrono::steady_clock::time_point created_at;
    bool holds_noise_handshake_slot = false;

    bool should_close() const {
        return socket->dead() ||
               (protocol == WireProtocol::Sv2Noise && noise_connection->terminal()) ||
               session->should_close();
    }
};

struct ServerWorker {
    int epoll_fd = -1;
    int event_fd = -1; // acceptor pokes it to deliver new connections
    std::mutex queue_mutex;
    std::vector<IncomingConnection> incoming; // accepted connections awaiting adoption
    std::atomic<size_t> pending{0};            // incoming.size() visible to the accept gate
    std::unordered_map<int, std::unique_ptr<ClientConnection>> connections;
    std::jthread thread;
};

namespace {

constexpr int kMaxEventsPerWait = 64;        // epoll_event batch size
constexpr int kEpollWaitTimeoutMs = 500;
constexpr size_t kReadChunkBytes = 4096;     // per-recv() read buffer
constexpr size_t kMaxReadBytesPerEvent = size_t{32} * 1024;
// Input a closing connection had already queued (a peer that reset after pipelining shares leaves
// them readable) is still processed, up to this bound, before the connection is removed.
constexpr size_t kMaxDrainBytesAfterClose = size_t{64} * 1024;
constexpr int kListenBacklog = 1024;
constexpr std::chrono::milliseconds kAcceptErrorBackoff{100};
constexpr int kProxyHeaderTimeoutMs = 2000;  // PROXY header read deadline
// PROXY-header reads run on this bounded pool, off the acceptor thread, so a stalled/partial header
// can't block accept(). Excess past the queue cap is shed. Both bounds count toward max_clients.
constexpr unsigned kProxyReaderThreads = 4;
constexpr size_t kMaxProxyQueue = 256;
constexpr size_t kMaxIncompleteNoiseHandshakes = 32;
constexpr size_t kSv2AdmissionLimitNumerator = 3;
constexpr size_t kSv2AdmissionLimitDenominator = 4;
constexpr std::chrono::seconds kEvictionSweepInterval{1};
constexpr std::chrono::seconds kNoiseHandshakeTimeout{10};
constexpr std::size_t kNoiseCertificateVersionOffset = 0;
constexpr std::size_t kNoiseCertificateExpiryOffset = 6;
constexpr uint16_t kSupportedNoiseCertificateVersion = 0;

constexpr size_t sv2_admission_limit(int max_clients) {
    if (max_clients <= 0)
        return 0;
    return static_cast<size_t>(max_clients) * kSv2AdmissionLimitNumerator /
           kSv2AdmissionLimitDenominator;
}

class SecretBytes {
public:
    explicit SecretBytes(std::size_t expected_size)
        : bytes_(expected_size + 1), expected_size_(expected_size) {}

    ~SecretBytes() {
        volatile uint8_t* output = bytes_.data();
        for (std::size_t index = 0; index < bytes_.size(); ++index)
            output[index] = 0;
    }

    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;

    [[nodiscard]] uint8_t* data() noexcept { return bytes_.data(); }
    [[nodiscard]] std::size_t read_capacity() const noexcept {
        return bytes_.size();
    }
    [[nodiscard]] std::size_t expected_size() const noexcept {
        return expected_size_;
    }
    [[nodiscard]] ByteView view() const {
        return ByteView(bytes_.data(), expected_size_);
    }

private:
    Bytes bytes_;
    std::size_t expected_size_;
};

// Raw read(), not ifstream: a stream buffer would hold a copy of the secret we cannot wipe.
void read_exact_secret_file(const std::string& path, SecretBytes& output,
                            std::string_view description) {
    int file_descriptor;
    do {
        file_descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    } while (file_descriptor < 0 && errno == EINTR);
    util::UniqueFd input(file_descriptor);
    if (!input)
        throw std::runtime_error("cannot open SV2 " +
                                 std::string(description) + " file: " + path);

    std::size_t total_bytes_read = 0;
    while (total_bytes_read < output.read_capacity()) {
        const ssize_t bytes_read =
            ::read(input.get(), output.data() + total_bytes_read,
                   output.read_capacity() - total_bytes_read);
        if (bytes_read > 0) {
            total_bytes_read += static_cast<std::size_t>(bytes_read);
            continue;
        }
        if (bytes_read == 0)
            break;
        if (errno == EINTR)
            continue;
        const int error_number = errno;
        throw std::runtime_error(
            "cannot read SV2 " + std::string(description) + " file: " +
            path + ": " + std::strerror(error_number));
    }
    if (total_bytes_read != output.expected_size())
        throw std::runtime_error(
            "SV2 " + std::string(description) + " file " + path +
            " must contain exactly " +
            std::to_string(output.expected_size()) + " raw bytes");
}

Bytes read_exact_binary_file(const std::string& path, std::size_t expected_size,
                             std::string_view description) {
    std::ifstream input(path, std::ios::binary);
    if (!input)
        throw std::runtime_error("cannot open SV2 " + std::string(description) +
                                 " file: " + path);

    Bytes bytes(expected_size + 1);
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    const std::size_t actual_size = static_cast<std::size_t>(input.gcount());
    if (input.bad())
        throw std::runtime_error("cannot read SV2 " + std::string(description) +
                                 " file: " + path);
    if (actual_size != expected_size)
        throw std::runtime_error("SV2 " + std::string(description) + " file " + path +
                                 " must contain exactly " + std::to_string(expected_size) +
                                 " raw bytes");
    bytes.resize(expected_size);
    return bytes;
}

std::optional<int64_t> noise_certificate_expiry(ByteView certificate) {
    if (util::read_le16(certificate.data() +
                        kNoiseCertificateVersionOffset) !=
        kSupportedNoiseCertificateVersion)
        return std::nullopt;
    return static_cast<int64_t>(util::read_le32(
        certificate.data() + kNoiseCertificateExpiryOffset));
}

uint32_t current_unix_time() {
    const std::time_t now = std::time(nullptr);
    if (now < 0 ||
        static_cast<uint64_t>(now) > std::numeric_limits<uint32_t>::max())
        throw std::runtime_error("current Unix time is outside the SV2 certificate range");
    return static_cast<uint32_t>(now);
}

void set_nonblocking(int fd) {
    int flags;
    do {
        flags = ::fcntl(fd, F_GETFL, 0);
    } while (flags < 0 && errno == EINTR);
    if (flags < 0) {
        const int error = errno;
        throw std::runtime_error(std::string("fcntl(F_GETFL) failed: ") +
                                 std::strerror(error));
    }

    int result;
    do {
        result = ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
        const int error = errno;
        throw std::runtime_error(std::string("fcntl(F_SETFL) failed: ") +
                                 std::strerror(error));
    }
}

int bind_listener(const std::string& host, uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        throw std::runtime_error(std::string("socket() failed: ") + std::strerror(errno));

    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef TCP_DEFER_ACCEPT
    const int defer_accept_seconds = 10;
    ::setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer_accept_seconds, sizeof(defer_accept_seconds));
#endif

    sockaddr_in bind_address{};
    bind_address.sin_family = AF_INET;
    bind_address.sin_port = htons(port);
    if (host.empty() || host == "0.0.0.0")
        bind_address.sin_addr.s_addr = INADDR_ANY;
    else if (inet_pton(AF_INET, host.c_str(), &bind_address.sin_addr) != 1) {
        ::close(fd);
        throw std::runtime_error("invalid bind host: " + host);
    }

    if (::bind(fd, reinterpret_cast<sockaddr*>(&bind_address), sizeof(bind_address)) < 0) {
        const int code = errno;
        const std::string error = "bind " + host + ":" + std::to_string(port) +
                                  " failed: " + std::strerror(code);
        ::close(fd);
        throw std::runtime_error(error);
    }
    if (::listen(fd, kListenBacklog) < 0) {
        const int code = errno;
        const std::string error =
            std::string("listen() failed: ") + std::strerror(code);
        ::close(fd);
        throw std::runtime_error(error);
    }
    try {
        set_nonblocking(fd);
    } catch (...) {
        ::close(fd);
        throw;
    }
    return fd;
}

} // namespace

namespace {

unsigned usable_cpu_count() {
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof(set), &set) == 0) {
        const int count = CPU_COUNT(&set);
        if (count > 0)
            return static_cast<unsigned>(count);
    }
    return std::max(1u, std::thread::hardware_concurrency()); // fall back if the query fails
}
} // namespace

unsigned resolve_worker_count(int configured) {
    if (configured > 0)
        return static_cast<unsigned>(configured);
    constexpr unsigned kMaxAutoWorkers = 16;
    return std::min(usable_cpu_count(), kMaxAutoWorkers);
}

Server::Server(Pool& pool, const Config& config)
    : pool_(pool),
      host_(config.bind_host),
      ports_(config.stratum_ports()),
      sv2_host_(config.sv2_host),
      sv2_ports_(config.sv2_ports),
      sv2_static_secret_key_file_(config.sv2_static_secret_key_file),
      sv2_authority_public_key_file_(config.sv2_authority_public_key_file),
      sv2_certificate_file_(config.sv2_certificate_file),
      sv2_plaintext_host_(config.sv2_plaintext_host),
      sv2_plaintext_ports_(config.sv2_plaintext_ports),
      max_clients_(config.max_clients),
      max_line_bytes_(config.max_line_bytes),
      drop_idle_seconds_(config.drop_idle_seconds),
      auth_timeout_seconds_(config.auth_timeout_seconds),
      max_protocol_errors_(config.max_protocol_errors),
      work_rebroadcast_seconds_(config.work_rebroadcast_seconds),
      proxy_protocol_from_(config.proxy_protocol_from),
      worker_count_(resolve_worker_count(config.worker_threads)) {}

void Server::reload_config(const RuntimeConfig& config) noexcept {
    max_clients_.store(config.max_clients, std::memory_order_relaxed);
    drop_idle_seconds_.store(config.drop_idle_seconds, std::memory_order_relaxed);
    auth_timeout_seconds_.store(config.auth_timeout_seconds, std::memory_order_relaxed);
    max_protocol_errors_.store(config.max_protocol_errors, std::memory_order_relaxed);
    work_rebroadcast_seconds_.store(config.work_rebroadcast_seconds,
                                    std::memory_order_relaxed);
}

// Out-of-line so ServerWorker is complete at the point unique_ptr is destroyed.
Server::~Server() = default;

void Server::bind_listener_group(const std::string& host,
                                 const std::vector<uint16_t>& ports,
                                 WireProtocol protocol) {
    std::vector<Listener> pending;
    pending.reserve(ports.size());
    for (uint16_t port : ports)
        pending.push_back(
            {util::UniqueFd(bind_listener(host, port)), port, protocol});

    listeners_.reserve(listeners_.size() + pending.size());
    for (Listener& listener : pending)
        listeners_.push_back(std::move(listener));
}

void Server::start_authenticated_sv2() {
    if (sv2_ports_.empty())
        return;

    try {
        {
            SecretBytes static_secret(SV2_NOISE_SECRET_KEY_SIZE);
            read_exact_secret_file(sv2_static_secret_key_file_, static_secret,
                                   "static secret key");
            const Bytes authority_public_key = read_exact_binary_file(
                sv2_authority_public_key_file_, SV2_NOISE_PUBLIC_KEY_SIZE,
                "authority public key");
            const Bytes certificate = read_exact_binary_file(
                sv2_certificate_file_, SV2_NOISE_CERTIFICATE_SIZE,
                "certificate");

            sv2_certificate_expiry_timestamp_ =
                noise_certificate_expiry(certificate);
            pool_.set_sv2_authenticated_state(
                false, sv2_certificate_expiry_timestamp_);

            auto credentials = sv2::NoiseCredentials::load(
                static_secret.view(), authority_public_key, certificate,
                current_unix_time());
            if (!credentials)
                throw std::runtime_error(
                    std::string("invalid SV2 Noise credentials: ") +
                    sv2_noise_status_string(credentials.error()));
            sv2_noise_credentials_ = std::move(*credentials);
        }

        bind_listener_group(sv2_host_, sv2_ports_, WireProtocol::Sv2Noise);
    } catch (const std::exception& error) {
        sv2_noise_credentials_.reset();
        pool_.set_sv2_authenticated_state(
            false, sv2_certificate_expiry_timestamp_);
        log::warning("Authenticated SV2 disabled; SV1 remains available: {}",
                     error.what());
        return;
    }

    pool_.set_sv2_authenticated_state(true,
                                      sv2_certificate_expiry_timestamp_);
    if (sv2_certificate_expiry_timestamp_)
        log::info("SV2 Noise certificate expires at Unix timestamp {}",
                  *sv2_certificate_expiry_timestamp_);
    for (uint16_t port : sv2_ports_)
        log::info("Authenticated SV2 listening on {}:{}", sv2_host_, port);
}

void Server::start_plaintext_sv2() {
    if (sv2_plaintext_ports_.empty())
        return;

    try {
        bind_listener_group(sv2_plaintext_host_, sv2_plaintext_ports_,
                            WireProtocol::Sv2Plaintext);
    } catch (const std::exception& error) {
        log::warning(
            "SV2 plaintext development listeners disabled; SV1 remains "
            "available: {}",
            error.what());
        return;
    }

    for (uint16_t port : sv2_plaintext_ports_)
        log::warning(
            "SV2 plaintext development listener on {}:{}; Noise transport is "
            "required before production use",
            sv2_plaintext_host_, port);
}

void Server::start() {
    bind_listener_group(host_, ports_, WireProtocol::Sv1);
    for (uint16_t port : ports_)
        log::info("Stratum listening on {}:{}", host_, port);

    pool_.set_sv2_authenticated_state(
        sv2_ports_.empty() ? std::nullopt : std::optional<bool>{false},
        std::nullopt);
    start_authenticated_sv2();
    start_plaintext_sv2();

    if (proxy_protocol_from_.empty()) {
        log::info("PROXY protocol: disabled (all connections direct)");
    } else {
        std::string sources;
        for (const auto& source : proxy_protocol_from_)
            sources += (sources.empty() ? "" : ", ") + source;
        log::info("PROXY protocol: trusting headers from {} source(s): {}", proxy_protocol_from_.size(),
                  sources);
        for (const auto& source : proxy_protocol_from_)
            if (!valid_trusted_source(source))
                log::warning("PROXY protocol: trusted source \"{}\" is not a valid IP or IPv4 CIDR; "
                             "it will never match (check for stray characters)",
                             source);
    }
}

uint16_t Server::bound_port(WireProtocol protocol) const {
    const auto listener =
        std::ranges::find_if(listeners_, [protocol](const Listener& value) {
            return value.protocol == protocol;
        });
    if (listener == listeners_.end())
        throw std::logic_error("listener is not started");

    sockaddr_in address{};
    socklen_t address_size = sizeof(address);
    if (::getsockname(listener->socket.get(),
                      reinterpret_cast<sockaddr*>(&address),
                      &address_size) < 0)
        throw std::runtime_error(std::string("getsockname() failed: ") + std::strerror(errno));
    return ntohs(address.sin_port);
}

void Server::worker_loop(ServerWorker& worker, const std::stop_token& stop) {
    // Shared by every reactor so adding workers cannot multiply the log budget.
    static log::RateLimit disconnect_log{log::kOperationalMessageInterval,
                                         log::kOperationalMessageBurst};
    static log::RateLimit timeout_log;
    static log::RateLimit protocol_error_log;
    static log::RateLimit handler_error_log;
    static log::RateLimit noise_failure_log;
    const auto release_noise_handshake_slot = [this](ClientConnection* connection) {
        if (!connection->holds_noise_handshake_slot)
            return;
        connection->holds_noise_handshake_slot = false;
        release_noise_handshake();
    };

    const auto report_noise_failure = [this](ClientConnection* connection) {
        if (connection->protocol != WireProtocol::Sv2Noise ||
            !connection->noise_connection->terminal())
            return;

        const sv2_noise_status status =
            connection->noise_connection->failure_status();
        if (status == SV2_NOISE_ERROR_CERTIFICATE_EXPIRED ||
            status == SV2_NOISE_ERROR_CERTIFICATE_NOT_YET_VALID) {
            pool_.set_sv2_authenticated_state(
                false, sv2_certificate_expiry_timestamp_);
            if (!certificate_validity_warning_logged_.exchange(
                    true, std::memory_order_relaxed)) {
                log::warning(
                    "SV2 Noise handshake failed for {}: {}; new authenticated "
                    "SV2 sessions are unavailable until valid credentials are "
                    "loaded",
                    connection->socket->peer(),
                    sv2_noise_status_string(status));
            }
            return;
        }

        const std::string_view phase =
            connection->noise_connection->handshake_complete()
                ? "transport"
                : "handshake";
        const std::string_view reason =
            status == SV2_NOISE_OK
                ? "invalid encrypted stream"
                : sv2_noise_status_string(status);
        log::message_limited(log::Level::Debug, noise_failure_log,
                             "SV2 Noise {} failed for {}: {}", phase,
                             connection->socket->peer(), reason);
    };

    const auto finish_noise_transport = [](ClientConnection* connection) {
        if (connection->protocol == WireProtocol::Sv2Noise &&
            connection->noise_connection)
            static_cast<void>(connection->noise_connection->finish());
    };

    // `connection` dangles after this; callers must not touch it again.
    const auto remove_connection = [&](ClientConnection* connection) {
        const int fd = connection->fd;
        release_noise_handshake_slot(connection);
        finish_noise_transport(connection);
        connection->socket->detach_reactor();
        ::epoll_ctl(worker.epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
        pool_.remove_client(connection->session);
        if (connection->protocol != WireProtocol::Sv2Noise ||
            connection->noise_connection->handshake_complete()) {
            if (connection->protocol == WireProtocol::Sv1 ||
                connection->session->ever_authorized())
                log::message_limited(log::Level::Info, disconnect_log,
                                     "Client disconnected: {}", connection->socket->peer());
            else
                log::message_limited(log::Level::Debug, disconnect_log,
                                     "Client disconnected before authorization: {}",
                                     connection->socket->peer());
        }
        worker.connections.erase(fd); // dtor closes the fd
    };

    // Whether a closing connection's queued input can still be parsed. SV1 lines stay framed after a
    // failed write or a control-budget close; SV2 needs an intact stream and session.
    const auto drains_before_close = [](const ClientConnection* connection) {
        switch (connection->protocol) {
        case WireProtocol::Sv1:
            return true;
        case WireProtocol::Sv2Plaintext:
            return !connection->session->should_close();
        case WireProtocol::Sv2Noise:
            return !connection->noise_connection->terminal() &&
                   !connection->session->should_close();
        }
        return false;
    };

    // Returns false once the connection has been removed. A connection that must close keeps
    // reading until its queued input is exhausted or kMaxDrainBytesAfterClose is spent.
    const auto handle_readable = [&](ClientConnection* connection) -> bool {
        char chunk[kReadChunkBytes];
        size_t consumed_this_event = 0;
        size_t drained_after_close = 0;
        bool draining = false;
        const auto event_time = std::chrono::steady_clock::now();
        while (true) {
            const ssize_t n = ::recv(connection->fd, chunk, sizeof(chunk), 0);
            if (n > 0) {
                consumed_this_event += static_cast<size_t>(n);
                if (draining)
                    drained_after_close += static_cast<size_t>(n);
                connection->last_activity = event_time;
                connection->socket->cork();
                if (connection->protocol == WireProtocol::Sv1) {
                    connection->buffer.append(chunk, static_cast<size_t>(n));
                    // Scan with a moving offset and erase the consumed prefix once at the end, not
                    // per line (which would be quadratic on a pipelined burst).
                    size_t start = 0;
                    size_t newline;
                    while ((newline = connection->buffer.find('\n', start)) != std::string::npos) {
                        std::string_view line(connection->buffer.data() + start, newline - start);
                        if (line.size() > max_line_bytes_)
                            break;
                        start = newline + 1;
                        if (!line.empty() && line.back() == '\r')
                            line.remove_suffix(1);
                        if (!line.empty())
                            connection->sv1_session->handle_line(line);
                    }
                    if (start > 0)
                        connection->buffer.erase(0, start);
                } else if (connection->protocol == WireProtocol::Sv2Noise) {
                    const auto* data = reinterpret_cast<const uint8_t*>(chunk);
                    const bool handshake_was_complete =
                        connection->noise_connection->handshake_complete();
                    Bytes plaintext = connection->noise_connection->receive(
                        ByteView(data, static_cast<size_t>(n)));
                    if (!handshake_was_complete &&
                        connection->noise_connection->handshake_complete()) {
                        release_noise_handshake_slot(connection);
                        pool_.set_sv2_authenticated_state(
                            true, sv2_certificate_expiry_timestamp_);
                        certificate_validity_warning_logged_.store(
                            false, std::memory_order_relaxed);
                    }
                    if (!plaintext.empty())
                        connection->sv2_session->handle_bytes(plaintext);
                } else {
                    const auto* data = reinterpret_cast<const uint8_t*>(chunk);
                    connection->sv2_session->handle_bytes(
                        ByteView(data, static_cast<size_t>(n)));
                }
                connection->socket->uncork();

                const int max_protocol_errors =
                    max_protocol_errors_.load(std::memory_order_relaxed);
                if (max_protocol_errors > 0 &&
                    connection->session->protocol_errors() >= max_protocol_errors) {
                    log::message_limited(
                        log::Level::Info, protocol_error_log,
                        "Client {} exceeded the protocol-error budget ({}); disconnecting",
                        connection->socket->peer(), max_protocol_errors);
                    remove_connection(connection);
                    return false;
                }
                if (connection->should_close()) {
                    if (!drains_before_close(connection) ||
                        drained_after_close >= kMaxDrainBytesAfterClose) {
                        report_noise_failure(connection);
                        remove_connection(connection);
                        return false;
                    }
                    draining = true;
                }
                if (connection->protocol == WireProtocol::Sv1 &&
                    connection->buffer.size() > max_line_bytes_) {
                    log::message_limited(log::Level::Info, protocol_error_log,
                                         "Client {} sent an over-long line; disconnecting",
                                         connection->socket->peer());
                    remove_connection(connection);
                    return false;
                }
                // Yield to other connections after the per-event budget; level-triggered EPOLLIN
                // re-fires for what's still buffered, so no data is lost. A draining connection
                // finishes now instead: it is bounded by kMaxDrainBytesAfterClose.
                if (!draining && consumed_this_event >= kMaxReadBytesPerEvent)
                    return true;
                continue;
            }
            if (n == 0) { // orderly EOF
                if (connection->protocol == WireProtocol::Sv2Noise &&
                    !connection->noise_connection->finish())
                    log::message_limited(log::Level::Debug, noise_failure_log,
                                         "Incomplete SV2 Noise stream from {}",
                                         connection->socket->peer());
                remove_connection(connection);
                return false;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (!draining)
                    return true; // socket drained
                remove_connection(connection); // closing, and nothing more is queued
                return false;
            }
            if (errno == EINTR)
                continue;
            remove_connection(connection); // hard error
            return false;
        }
    };

    // Remove a connection that must close, first processing input it already queued.
    const auto reap = [&](ClientConnection* connection) {
        try {
            if (drains_before_close(connection) && !handle_readable(connection))
                return; // drained and removed
        } catch (const std::exception& e) {
            log::message_limited(log::Level::Warning, handler_error_log,
                                 "Client {} handler error ({}); disconnecting",
                                 connection->socket->peer(), e.what());
        }
        report_noise_failure(connection);
        remove_connection(connection);
    };

    // Adopt accepted fds: create the session and register with epoll.
    const auto drain_incoming = [&]() {
        std::vector<IncomingConnection> batch;
        {
            const std::scoped_lock lock(worker.queue_mutex);
            batch.swap(worker.incoming);
        }
        for (auto& incoming : batch) {
            const int fd = incoming.fd;
            std::shared_ptr<SocketConnection> socket;
            std::shared_ptr<mining::Client> registered_session;
            std::unique_ptr<ClientConnection> connection;
            try {
                set_nonblocking(fd);
                socket = std::make_shared<SocketConnection>(
                    fd, work_rebroadcast_seconds_.load(std::memory_order_relaxed),
                    std::move(incoming.peer));
                connection = std::make_unique<ClientConnection>();
                connection->fd = fd;
                connection->protocol = incoming.protocol;
                connection->holds_noise_handshake_slot =
                    incoming.protocol == WireProtocol::Sv2Noise;
                connection->socket = socket;
                if (incoming.protocol == WireProtocol::Sv1) {
                    connection->sv1_session = pool_.add_client(connection->socket);
                    connection->session = connection->sv1_session;
                } else if (incoming.protocol == WireProtocol::Sv2Noise) {
                    if (!sv2_noise_credentials_)
                        throw std::logic_error("SV2 Noise credentials are not loaded");
                    connection->noise_connection =
                        std::make_shared<sv2::NoiseConnection>(
                            connection->socket, sv2_noise_credentials_,
                            static_cast<uint32_t>(max_line_bytes_));
                    connection->sv2_session =
                        pool_.add_sv2_client(connection->noise_connection);
                    connection->session = connection->sv2_session;
                } else {
                    connection->sv2_session = pool_.add_sv2_client(connection->socket);
                    connection->session = connection->sv2_session;
                }
                registered_session = connection->session;
                const auto created = std::chrono::steady_clock::now();
                connection->last_activity = created;
                connection->created_at = created;
                // Set before registering the fd, with the same data ptr epoll uses below, so the
                // socket can (dis)arm EPOLLOUT as its outbox fills/drains.
                connection->socket->attach_reactor(worker.epoll_fd, connection.get());
                epoll_event event{};
                event.events = EPOLLIN;
                event.data.ptr = connection.get();
                if (::epoll_ctl(worker.epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
                    release_noise_handshake_slot(connection.get());
                    finish_noise_transport(connection.get());
                    socket->detach_reactor();
                    pool_.remove_client(connection->session);
                    worker.pending.fetch_sub(1, std::memory_order_relaxed);
                    continue; // dropping the connection closes the fd
                }
                worker.connections.emplace(fd, std::move(connection));
            } catch (const std::exception& error) {
                // One failed adoption must not kill the reactor and strand its other clients.
                ::epoll_ctl(worker.epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
                if (socket)
                    socket->detach_reactor();
                if (registered_session)
                    pool_.remove_client(registered_session);
                if (connection)
                    release_noise_handshake_slot(connection.get());
                else if (incoming.protocol == WireProtocol::Sv2Noise)
                    release_noise_handshake();
                if (!socket)
                    ::close(fd);
                static log::RateLimit adoption_log;
                log::message_limited(log::Level::Warning, adoption_log,
                                     "Could not adopt a mining client: {}", error.what());
            }
            worker.pending.fetch_sub(1, std::memory_order_relaxed);
        }
    };

    // Evict silent (idle) and never-authorized connections.
    const auto sweep_expired = [&]() {
        const auto now = std::chrono::steady_clock::now();
        const int drop_idle_seconds = drop_idle_seconds_.load(std::memory_order_relaxed);
        const int auth_timeout_seconds = auth_timeout_seconds_.load(std::memory_order_relaxed);
        std::vector<ClientConnection*> closing;
        std::vector<ClientConnection*> expired;
        for (auto& [fd, connection] : worker.connections) {
            if (connection->should_close()) {
                closing.push_back(connection.get());
            } else if (connection->protocol == WireProtocol::Sv2Noise &&
                !connection->noise_connection->handshake_complete() &&
                now - connection->created_at > kNoiseHandshakeTimeout) {
                log::message_limited(log::Level::Debug, noise_failure_log,
                                     "SV2 Noise handshake timed out for {}",
                                     connection->socket->peer());
                expired.push_back(connection.get());
            } else if (drop_idle_seconds > 0 &&
                now - connection->last_activity > std::chrono::seconds(drop_idle_seconds)) {
                log::message_limited(log::Level::Info, timeout_log,
                                     "Client {} idle for over {}s; disconnecting",
                                     connection->socket->peer(), drop_idle_seconds);
                expired.push_back(connection.get());
            } else if (auth_timeout_seconds > 0 &&
                       now - connection->created_at > std::chrono::seconds(auth_timeout_seconds) &&
                       !connection->session->ever_authorized()) {
                log::message_limited(log::Level::Info, timeout_log,
                                     "Client {} did not authorize within {}s; disconnecting",
                                     connection->socket->peer(), auth_timeout_seconds);
                expired.push_back(connection.get());
            }
        }
        for (ClientConnection* connection : closing)
            reap(connection);
        for (ClientConnection* connection : expired)
            remove_connection(connection);
    };

    epoll_event events[kMaxEventsPerWait];
    const bool has_sv2_listeners =
        std::ranges::any_of(listeners_, [](const Listener& listener) {
            return listener.protocol != WireProtocol::Sv1;
        });
    auto last_sweep = std::chrono::steady_clock::now();
    auto last_sv2_maintenance = last_sweep;
    while (!stop.stop_requested()) {
        int wait_timeout_ms = kEpollWaitTimeoutMs;
        if (has_sv2_listeners) {
            const auto maintenance_deadline =
                last_sv2_maintenance + sv2::kStandardJobRefreshInterval;
            const auto before_wait = std::chrono::steady_clock::now();
            wait_timeout_ms =
                maintenance_deadline <= before_wait
                    ? 0
                    : static_cast<int>(
                          std::chrono::ceil<std::chrono::milliseconds>(
                              maintenance_deadline - before_wait)
                              .count());
        }
        const int ready =
            ::epoll_wait(worker.epoll_fd, events, kMaxEventsPerWait, wait_timeout_ms);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        for (int i = 0; i < ready; ++i) {
            if (events[i].data.ptr == nullptr) { // eventfd: new connections to adopt
                uint64_t drained;
                while (::read(worker.event_fd, &drained, sizeof(drained)) > 0) {
                }
                drain_incoming();
                continue;
            }
            ClientConnection* connection = static_cast<ClientConnection*>(events[i].data.ptr);
            try {
                // EPOLLHUP/EPOLLERR can arrive with readable final bytes. Consume them first so a
                // miner's last share (including a block candidate) is not discarded on close;
                // handle_readable reaps the connection itself once the read hits EOF or errors.
                const uint32_t event = events[i].events;
                if ((event & (EPOLLIN | EPOLLHUP | EPOLLERR)) && !handle_readable(connection))
                    continue;
                if (event & EPOLLOUT) {
                    if (!connection->socket->flush_outbox()) {
                        reap(connection);
                        continue;
                    }
                }
            } catch (const std::exception& e) {
                // Isolate: one bad message drops only this client, not the reactor.
                log::message_limited(log::Level::Warning, handler_error_log,
                                     "Client {} handler error ({}); disconnecting",
                                     connection->socket->peer(), e.what());
                remove_connection(connection);
            }
        }

        // Time-based eviction sweep, independent of event volume (gating on ready == 0 would
        // starve it on a busy reactor).
        const auto now = std::chrono::steady_clock::now();
        if (has_sv2_listeners &&
            now - last_sv2_maintenance >= sv2::kStandardJobRefreshInterval) {
            for (auto& entry : worker.connections) {
                auto& connection = entry.second;
                if (connection->protocol != WireProtocol::Sv1 &&
                    (connection->protocol != WireProtocol::Sv2Noise ||
                     connection->noise_connection->handshake_complete()))
                    connection->sv2_session->maybe_refresh_job();
            }
            last_sv2_maintenance = now;
        }
        if (now - last_sweep >= kEvictionSweepInterval) {
            sweep_expired();
            last_sweep = now;
        }
    }

    // Shutdown: detach every connection from epoll first (so still-running work/vardiff threads
    // can't epoll_ctl against records we free or the epoll fd we close below), then drop them.
    for (auto& [fd, connection] : worker.connections) {
        release_noise_handshake_slot(connection.get());
        finish_noise_transport(connection.get());
        connection->socket->detach_reactor();
        pool_.remove_client(connection->session);
    }
    worker.connections.clear();
    // Close any fds accepted but never adopted -- nothing else owns them.
    {
        const std::scoped_lock lock(worker.queue_mutex);
        for (auto& incoming : worker.incoming) {
            if (incoming.protocol == WireProtocol::Sv2Noise)
                release_noise_handshake();
            ::close(incoming.fd);
        }
        worker.incoming.clear();
        worker.pending.store(0, std::memory_order_relaxed);
    }
    if (worker.epoll_fd >= 0)
        ::close(worker.epoll_fd);
    if (worker.event_fd >= 0)
        ::close(worker.event_fd);
}

void Server::deliver_to_worker(size_t worker_index, int fd, std::string peer,
                               WireProtocol protocol) {
    ServerWorker& worker = *workers_[worker_index];
    {
        const std::scoped_lock lock(worker.queue_mutex);
        worker.incoming.push_back({fd, std::move(peer), protocol});
        worker.pending.fetch_add(1, std::memory_order_relaxed);
    }
    const uint64_t one = 1;
    const ssize_t written = ::write(worker.event_fd, &one, sizeof(one));
    (void)written;
}

bool Server::reserve_noise_handshake() {
    size_t count = incomplete_noise_handshakes_.load(std::memory_order_relaxed);
    while (count < kMaxIncompleteNoiseHandshakes) {
        if (incomplete_noise_handshakes_.compare_exchange_weak(
                count, count + 1, std::memory_order_relaxed))
            return true;
    }
    return false;
}

void Server::release_noise_handshake() {
    incomplete_noise_handshakes_.fetch_sub(1, std::memory_order_relaxed);
}

bool Server::enqueue_proxy_read(int fd, std::string peer, size_t worker_index) {
    {
        const std::scoped_lock lock(proxy_mutex_);
        if (proxy_queue_.size() >= kMaxProxyQueue)
            return false; // shed load: the bounded queue is full
        proxy_queue_.push_back({fd, std::move(peer), worker_index});
    }
    proxy_pending_.fetch_add(1, std::memory_order_relaxed);
    proxy_cv_.notify_one();
    return true;
}

void Server::proxy_reader_loop(const std::stop_token& stop) {
    while (!stop.stop_requested()) {
        PendingProxyConn job;
        {
            std::unique_lock<std::mutex> lock(proxy_mutex_);
            proxy_cv_.wait(lock, stop, [this] { return !proxy_queue_.empty(); });
            if (proxy_queue_.empty())
                continue; // woken by stop with nothing to do
            job = std::move(proxy_queue_.front());
            proxy_queue_.pop_front();
        }
        // The blocking read happens here, on a pool thread, never on the acceptor.
        const auto header = read_proxy_header(job.fd, kProxyHeaderTimeoutMs);
        if (header.kind == ProxyHeaderKind::Malformed) {
            static log::RateLimit malformed_proxy_log;
            log::message_limited(
                log::Level::Warning, malformed_proxy_log,
                "PROXY protocol: malformed header from {}; dropping (first bytes: {})",
                job.peer, header.detail);
            ::close(job.fd);
        } else {
            std::string peer;
            if (header.kind == ProxyHeaderKind::RealAddress)
                peer = header.address;   // header carried the real client addr
            else
                peer = std::move(job.peer); // Direct: keep the TCP peer
            deliver_to_worker(job.worker_index, job.fd, std::move(peer), WireProtocol::Sv1);
        }
        proxy_pending_.fetch_sub(1, std::memory_order_relaxed);
    }
}

void Server::run(const std::stop_token& stop) {
    for (unsigned i = 0; i < worker_count_; ++i) {
        auto worker = std::make_unique<ServerWorker>();
        worker->epoll_fd = ::epoll_create1(0);
        worker->event_fd = ::eventfd(0, EFD_NONBLOCK);
        if (worker->epoll_fd < 0 || worker->event_fd < 0)
            throw std::runtime_error("epoll/eventfd setup failed");
        epoll_event event{};
        event.events = EPOLLIN;
        event.data.ptr = nullptr;
        ::epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, worker->event_fd, &event);
        ServerWorker* worker_ptr = worker.get();
        worker->thread =
            std::jthread([this, worker_ptr](const std::stop_token& st) { worker_loop(*worker_ptr, st); });
        workers_.push_back(std::move(worker));
    }
    log::info("Mining reactor: {} threads", worker_count_);

    // Only spin up the reader pool when PROXY protocol is enabled.
    if (!proxy_protocol_from_.empty()) {
        for (unsigned i = 0; i < kProxyReaderThreads; ++i)
            proxy_readers_.emplace_back(
                [this](const std::stop_token& st) { proxy_reader_loop(st); });
        log::info("PROXY-header reader pool: {} threads", kProxyReaderThreads);
    }

    std::vector<pollfd> poll_fds;
    poll_fds.reserve(listeners_.size());
    for (const auto& listener : listeners_)
        poll_fds.push_back({listener.socket.get(), POLLIN, 0});

    size_t next_worker = 0;
    log::RateLimit accept_error_log;
    log::RateLimit admission_log;
    log::RateLimit proxy_queue_log;
    log::RateLimit noise_admission_log;
    std::mutex accept_retry_mutex;
    std::condition_variable_any accept_retry_cv;
    while (!stop.stop_requested()) {
        for (auto& poll_fd : poll_fds)
            poll_fd.revents = 0;
        const int ready = ::poll(poll_fds.data(), static_cast<nfds_t>(poll_fds.size()), 500);
        if (ready <= 0)
            continue;

        for (size_t i = 0; i < poll_fds.size() && !stop.stop_requested(); ++i) {
            if (!(poll_fds[i].revents & POLLIN))
                continue;
            while (!stop.stop_requested()) {
                sockaddr_storage addr{};
                socklen_t addr_len = sizeof(addr);
                const int fd =
                    ::accept(listeners_[i].socket.get(),
                             reinterpret_cast<sockaddr*>(&addr), &addr_len);
                if (fd < 0) {
                    const int accept_error = errno;
                    if (accept_error == EINTR || accept_error == ECONNABORTED)
                        continue;
                    if (accept_error == EAGAIN || accept_error == EWOULDBLOCK)
                        break;
                    log::message_limited(log::Level::Warning, accept_error_log,
                                         "Could not accept mining client: {}; retrying",
                                         std::strerror(accept_error));
                    // Resource exhaustion leaves the listener readable. Delay its next accept
                    // without holding up established miners on the independent reactors.
                    std::unique_lock retry_lock(accept_retry_mutex);
                    accept_retry_cv.wait_for(retry_lock, stop, kAcceptErrorBackoff,
                                             [] { return false; });
                    break;
                }
                // Capture the peer now -- a client that closes immediately would otherwise read
                // back "unknown" via a later getpeername().
                std::string peer = describe_peer(addr);
                // Count fds accepted-but-not-adopted (worker.incoming) and fds queued/being read
                // for a PROXY header (proxy_pending_) against the cap, else a burst between accept
                // and adoption overshoots max_clients.
                size_t pending_total = proxy_pending_.load(std::memory_order_relaxed);
                for (const auto& worker : workers_)
                    pending_total += worker->pending.load(std::memory_order_relaxed);
                const size_t occupied_slots = pool_.client_count() + pending_total;
                const int max_clients = max_clients_.load(std::memory_order_relaxed);
                if (occupied_slots >= static_cast<size_t>(max_clients)) {
                    log::message_limited(log::Level::Warning, admission_log,
                                         "Max clients ({}) reached; dropping connection",
                                         max_clients);
                    ::close(fd);
                    continue;
                }
                const WireProtocol protocol = listeners_[i].protocol;
                if (protocol != WireProtocol::Sv1 &&
                    occupied_slots >= sv2_admission_limit(max_clients)) {
                    log::message_limited(log::Level::Debug, noise_admission_log,
                                         "SV2 client limit reached; reserving capacity for SV1");
                    ::close(fd);
                    continue;
                }
                if (protocol == WireProtocol::Sv2Noise &&
                    !reserve_noise_handshake()) {
                    log::message_limited(log::Level::Debug, noise_admission_log,
                                         "SV2 Noise handshake limit reached; dropping connection");
                    ::close(fd);
                    continue;
                }
                if (protocol == WireProtocol::Sv1 &&
                    !proxy_protocol_from_.empty()) {
                    const std::string src_ip = peer.substr(0, peer.rfind(':'));
                    if (source_trusted(src_ip, proxy_protocol_from_)) {
                        // Defer the (up to ~2s) header read to the reader pool: doing it here would
                        // block accept() for every other connection. The pool delivers the fd once
                        // parsed.
                        const size_t worker_index = next_worker++ % worker_count_;
                        if (!enqueue_proxy_read(fd, std::move(peer), worker_index)) {
                            log::message_limited(
                                log::Level::Warning, proxy_queue_log,
                                "PROXY-header reader queue full; dropping connection");
                            ::close(fd);
                        }
                        continue;
                    }
                }
                // Direct connection (PROXY disabled or untrusted source): hand straight to a reactor.
                deliver_to_worker(next_worker++ % worker_count_, fd, std::move(peer),
                                  protocol);
            }
        }
    }

    // Stop the reader pool first -- its threads call deliver_to_worker (reference workers_), so
    // they must finish before the reactors are destroyed. A reader stuck in a header read exits
    // within kProxyHeaderTimeoutMs. Then close any still-queued fds.
    for (auto& reader : proxy_readers_)
        reader.request_stop();
    proxy_cv_.notify_all();
    proxy_readers_.clear(); // jthread dtor joins each reader
    {
        const std::scoped_lock lock(proxy_mutex_);
        for (auto& job : proxy_queue_)
            ::close(job.fd);
        proxy_queue_.clear();
        proxy_pending_.store(0, std::memory_order_relaxed);
    }

    for (auto& worker : workers_) {
        worker->thread.request_stop();
        const uint64_t one = 1;
        ssize_t written = ::write(worker->event_fd, &one, sizeof(one));
        (void)written;
    }
    workers_.clear();

    listeners_.clear();
}

} // namespace erikslund::net

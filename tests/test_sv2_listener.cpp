#include <doctest/doctest.h>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "bitcoin/work_source.hpp"
#include "core/config.hpp"
#include "net/server.hpp"
#include "pool/pool.hpp"
#include "work_generation_fixture.hpp"
#include "sv2/messages.hpp"
#include "sv2_noise_test_oracle.hpp"
#include "sv2/session.hpp"
#include "util/endian.hpp"

using namespace erikslund;

namespace {

constexpr std::size_t kReactorReadBudgetBytes = std::size_t{32} * 1024;
constexpr std::size_t kMaximumIncompleteNoiseHandshakes = 32;
constexpr int kReplyTimeoutMilliseconds = 2000;
constexpr std::size_t kChannelDiscriminatorBytes = 2;
constexpr std::string_view kRegtestAddress =
    "bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf";
constexpr std::string_view kSecondRegtestAddress =
    "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";

class FileDescriptor {
public:
    explicit FileDescriptor(int value) : value_(value) {}
    ~FileDescriptor() { close(); }

    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept
        : value_(std::exchange(other.value_, -1)) {}
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            close();
            value_ = std::exchange(other.value_, -1);
        }
        return *this;
    }

    [[nodiscard]] int get() const { return value_; }
    void close() noexcept {
        if (value_ >= 0) {
            ::close(value_);
            value_ = -1;
        }
    }

private:
    int value_;
};

class TemporaryNoiseCredentials {
public:
    explicit TemporaryNoiseCredentials(
        const sv2::test::InitiatorFixture& fixture,
        uint16_t certificate_version = 0)
        : directory_(std::filesystem::temp_directory_path() /
                     ("erikslund-sv2-listener-" + std::to_string(::getpid()) +
                      "-" + std::to_string(
                          std::chrono::steady_clock::now().time_since_epoch().count()))),
          static_secret_(directory_ / "static-secret.raw"),
          authority_public_(directory_ / "authority-public.raw"),
          certificate_(directory_ / "certificate.raw") {
        std::filesystem::create_directory(directory_);
        write(static_secret_, fixture.static_secret());
        write(authority_public_, fixture.authority_public());
        auto certificate = fixture.certificate();
        util::write_le16(certificate.data(), certificate_version);
        write(certificate_, certificate);
    }

    ~TemporaryNoiseCredentials() {
        std::error_code ignored;
        std::filesystem::remove_all(directory_, ignored);
    }

    TemporaryNoiseCredentials(const TemporaryNoiseCredentials&) = delete;
    TemporaryNoiseCredentials& operator=(const TemporaryNoiseCredentials&) = delete;

    [[nodiscard]] std::string static_secret() const {
        return static_secret_.string();
    }

    [[nodiscard]] std::string authority_public() const {
        return authority_public_.string();
    }

    [[nodiscard]] std::string certificate() const {
        return certificate_.string();
    }

    void replace_static_secret(std::size_t size) {
        write(static_secret_, Bytes(size, 0x42));
    }

private:
    template <typename BytesType>
    static void write(const std::filesystem::path& path, const BytesType& bytes) {
        std::ofstream output(path, std::ios::binary);
        if (!output)
            throw std::runtime_error("could not create temporary SV2 credential");
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
        if (!output)
            throw std::runtime_error("could not write temporary SV2 credential");
    }

    std::filesystem::path directory_;
    std::filesystem::path static_secret_;
    std::filesystem::path authority_public_;
    std::filesystem::path certificate_;
};

class UnusedWorkSource final : public bitcoin::WorkSource {
public:
    bitcoin::ChainInfo detect_chain() override {
        return {.chain = "regtest", .blocks = 0};
    }

    std::string get_tip() override {
        throw std::logic_error("unexpected tip request");
    }

    bitcoin::BlockTemplate fetch_template() override {
        throw std::logic_error("unexpected template request");
    }

    bitcoin::HeaderFacts fetch_header(const std::string&) override {
        throw std::logic_error("unexpected header request");
    }

    std::optional<std::string> submit_block_hex(const std::string&) override {
        throw std::logic_error("unexpected block submission");
    }
};

bitcoin::BlockTemplate listener_template() {
    bitcoin::BlockTemplate block_template;
    block_template.height = 170;
    block_template.version = 0x20000000;
    block_template.curtime = static_cast<uint32_t>(std::time(nullptr));
    block_template.bits = 0x207fffff;
    block_template.bits_hex = "207fffff";
    block_template.coinbase_value = 5000000000ULL;
    block_template.previousblockhash = std::string(64, 'a');
    block_template.coinbase_script_sig_prefix = {0x02, 0xaa, 0x00};
    return block_template;
}

class SeededWorkSource final : public bitcoin::WorkSource {
public:
    bitcoin::ChainInfo detect_chain() override {
        return {.chain = "regtest", .blocks = block_template_.height - 1};
    }

    std::string get_tip() override {
        return block_template_.previousblockhash;
    }

    bitcoin::BlockTemplate fetch_template() override {
        return block_template_;
    }

    bitcoin::HeaderFacts fetch_header(const std::string&) override {
        throw std::logic_error("unexpected header request");
    }

    std::optional<std::string> submit_block_hex(const std::string&) override {
        throw std::logic_error("unexpected block submission");
    }

private:
    bitcoin::BlockTemplate block_template_ = listener_template();
};

template <typename Predicate>
bool wait_until(Predicate&& predicate) {
    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(kReplyTimeoutMilliseconds);
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return predicate();
}

FileDescriptor connect_to(uint16_t port) {
    FileDescriptor client(::socket(AF_INET, SOCK_STREAM, 0));
    if (client.get() < 0)
        throw std::runtime_error("could not create test socket");

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(client.get(), reinterpret_cast<sockaddr*>(&address),
                  sizeof(address)) != 0)
        throw std::runtime_error(std::string("connect() failed: ") +
                                 std::strerror(errno));
    return client;
}

bool disconnected(int fd) {
    uint8_t byte;
    const ssize_t received = ::recv(fd, &byte, sizeof(byte), MSG_DONTWAIT);
    if (received == 0)
        return true;
    return received < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
           errno != EINTR;
}

void send_all(int fd, ByteView bytes) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t sent =
            ::send(fd, bytes.data() + offset, bytes.size() - offset, MSG_NOSIGNAL);
        if (sent > 0) {
            offset += static_cast<std::size_t>(sent);
            continue;
        }
        if (sent < 0 && errno == EINTR)
            continue;
        throw std::runtime_error(std::string("send() failed: ") + std::strerror(errno));
    }
}

void begin_incomplete_message(int fd) {
    const uint8_t byte = 0;
    send_all(fd, ByteView(&byte, 1));
}

ssize_t receive_some(int fd, uint8_t* bytes, std::size_t capacity) {
    pollfd event{fd, POLLIN, 0};
    int ready;
    do {
        ready = ::poll(&event, 1, kReplyTimeoutMilliseconds);
    } while (ready < 0 && errno == EINTR);
    if (ready == 0)
        throw std::runtime_error("timed out waiting for SV2 reply");
    if (ready < 0)
        throw std::runtime_error(std::string("poll() failed: ") + std::strerror(errno));

    ssize_t received;
    do {
        received = ::recv(fd, bytes, capacity, 0);
    } while (received < 0 && errno == EINTR);
    if (received < 0)
        throw std::runtime_error(std::string("recv() failed: ") + std::strerror(errno));
    return received;
}

Bytes receive_reply(int fd) {
    Bytes reply;
    while (true) {
        uint8_t chunk[256];
        const ssize_t received = receive_some(fd, chunk, sizeof(chunk));
        if (received > 0) {
            append(reply, ByteView(chunk, static_cast<std::size_t>(received)));
            continue;
        }
        return reply;
    }
}

Bytes receive_exact(int fd, std::size_t size) {
    Bytes bytes(size);
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t received =
            receive_some(fd, bytes.data() + offset, bytes.size() - offset);
        if (received == 0)
            throw std::runtime_error("connection closed before the expected SV2 bytes arrived");
        offset += static_cast<std::size_t>(received);
    }
    return bytes;
}

std::vector<sv2::Frame> receive_frames(int fd, std::size_t expected_count) {
    sv2::FrameDecoder decoder;
    std::vector<sv2::Frame> frames;
    while (frames.size() < expected_count) {
        uint8_t chunk[4096];
        const ssize_t received = receive_some(fd, chunk, sizeof(chunk));
        if (received == 0)
            throw std::runtime_error("SV2 connection closed before the initial work arrived");
        std::vector<sv2::Frame> decoded =
            decoder.push(ByteView(chunk, static_cast<std::size_t>(received)));
        frames.insert(frames.end(), decoded.begin(), decoded.end());
    }
    decoder.finish();
    return frames;
}

void run_and_stop(net::Server& server) {
    std::exception_ptr server_error;
    std::jthread server_thread([&](const std::stop_token& stop) {
        try {
            server.run(stop);
        } catch (...) {
            server_error = std::current_exception();
        }
    });
    server_thread.request_stop();
    server_thread.join();
    if (server_error)
        std::rethrow_exception(server_error);
}

} // namespace

TEST_CASE("SV2 leaves one quarter of the client limit available to SV1") {
    Config config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;
    config.sv2_plaintext_host = "127.0.0.1";
    config.sv2_plaintext_ports = {0};
    config.max_clients = 4;
    config.worker_threads = 1;
    config.drop_idle_seconds = 0;
    config.auth_timeout_seconds = 0;

    UnusedWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    net::Server server(pool, config);
    server.start();
    const uint16_t sv1_port = server.bound_port(net::WireProtocol::Sv1);
    const uint16_t sv2_port =
        server.bound_port(net::WireProtocol::Sv2Plaintext);

    std::exception_ptr server_error;
    std::jthread server_thread([&](const std::stop_token& stop) {
        try {
            server.run(stop);
        } catch (...) {
            server_error = std::current_exception();
        }
    });

    FileDescriptor first_sv2 = connect_to(sv2_port);
    FileDescriptor second_sv2 = connect_to(sv2_port);
    FileDescriptor third_sv2 = connect_to(sv2_port);
    begin_incomplete_message(first_sv2.get());
    begin_incomplete_message(second_sv2.get());
    begin_incomplete_message(third_sv2.get());
    REQUIRE(wait_until([&] { return pool.client_count() == 3; }));

    FileDescriptor rejected_sv2 = connect_to(sv2_port);
    begin_incomplete_message(rejected_sv2.get());
    REQUIRE(wait_until([&] { return disconnected(rejected_sv2.get()); }));
    REQUIRE(pool.client_count() == 3);

    FileDescriptor sv1 = connect_to(sv1_port);
    const std::string subscribe =
        R"({"id":1,"method":"mining.subscribe","params":["admission-test"]}
)";
    send_all(sv1.get(), ByteView(
                            reinterpret_cast<const uint8_t*>(subscribe.data()),
                            subscribe.size()));
    uint8_t reply[256];
    CHECK(receive_some(sv1.get(), reply, sizeof(reply)) > 0);
    CHECK(wait_until([&] { return pool.client_count() == 4; }));

    server_thread.request_stop();
    server_thread.join();
    if (server_error)
        std::rethrow_exception(server_error);
}

TEST_CASE("incomplete SV2 Noise handshakes are capped") {
    sv2::test::InitiatorFixture fixture;
    TemporaryNoiseCredentials credentials(fixture);

    Config config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;
    config.sv2_host = "127.0.0.1";
    config.sv2_ports = {0};
    config.sv2_static_secret_key_file = credentials.static_secret();
    config.sv2_authority_public_key_file = credentials.authority_public();
    config.sv2_certificate_file = credentials.certificate();
    config.max_clients = 64;
    config.worker_threads = 1;
    config.drop_idle_seconds = 0;
    config.auth_timeout_seconds = 0;

    UnusedWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    net::Server server(pool, config);
    server.start();
    const uint16_t port = server.bound_port(net::WireProtocol::Sv2Noise);

    std::exception_ptr server_error;
    std::jthread server_thread([&](const std::stop_token& stop) {
        try {
            server.run(stop);
        } catch (...) {
            server_error = std::current_exception();
        }
    });

    std::vector<FileDescriptor> incomplete_handshakes;
    incomplete_handshakes.reserve(kMaximumIncompleteNoiseHandshakes);
    for (std::size_t connection = 0;
         connection < kMaximumIncompleteNoiseHandshakes; ++connection) {
        incomplete_handshakes.push_back(connect_to(port));
        begin_incomplete_message(incomplete_handshakes.back().get());
    }
    REQUIRE(wait_until([&] {
        return pool.client_count() == kMaximumIncompleteNoiseHandshakes;
    }));

    FileDescriptor rejected = connect_to(port);
    begin_incomplete_message(rejected.get());
    REQUIRE(wait_until([&] { return disconnected(rejected.get()); }));
    REQUIRE(pool.client_count() == kMaximumIncompleteNoiseHandshakes);

    incomplete_handshakes.front().close();
    REQUIRE(wait_until([&] {
        return pool.client_count() == kMaximumIncompleteNoiseHandshakes - 1;
    }));
    FileDescriptor replacement = connect_to(port);
    begin_incomplete_message(replacement.get());
    REQUIRE(wait_until([&] {
        return pool.client_count() == kMaximumIncompleteNoiseHandshakes;
    }));

    server_thread.request_stop();
    server_thread.join();
    if (server_error)
        std::rethrow_exception(server_error);
}

TEST_CASE("expired SV2 credentials leave the SV1 listener available") {
    sv2::test::InitiatorFixture expired_fixture(0, 1);
    TemporaryNoiseCredentials credentials(expired_fixture);

    Config config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;
    config.sv2_host = "127.0.0.1";
    config.sv2_ports = {0};
    config.sv2_static_secret_key_file = credentials.static_secret();
    config.sv2_authority_public_key_file = credentials.authority_public();
    config.sv2_certificate_file = credentials.certificate();
    config.worker_threads = 1;

    UnusedWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    net::Server server(pool, config);
    CHECK_NOTHROW(server.start());
    CHECK(server.bound_port(net::WireProtocol::Sv1) != 0);
    CHECK_THROWS_AS(server.bound_port(net::WireProtocol::Sv2Noise),
                    std::logic_error);

    const api::PoolSnapshot snapshot = pool.snapshot();
    REQUIRE(snapshot.sv2_authenticated_ready.has_value());
    CHECK_FALSE(*snapshot.sv2_authenticated_ready);
    REQUIRE(snapshot.sv2_certificate_expiry_timestamp.has_value());
    CHECK(*snapshot.sv2_certificate_expiry_timestamp == 1);

    run_and_stop(server);
}

TEST_CASE("unsupported SV2 certificate versions do not export an untrusted expiry") {
    sv2::test::InitiatorFixture fixture;
    TemporaryNoiseCredentials credentials(fixture, 1);

    Config config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;
    config.sv2_host = "127.0.0.1";
    config.sv2_ports = {0};
    config.sv2_static_secret_key_file = credentials.static_secret();
    config.sv2_authority_public_key_file = credentials.authority_public();
    config.sv2_certificate_file = credentials.certificate();
    config.worker_threads = 1;

    UnusedWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    net::Server server(pool, config);
    CHECK_NOTHROW(server.start());
    CHECK(server.bound_port(net::WireProtocol::Sv1) != 0);
    CHECK_THROWS_AS(server.bound_port(net::WireProtocol::Sv2Noise),
                    std::logic_error);

    const api::PoolSnapshot snapshot = pool.snapshot();
    REQUIRE(snapshot.sv2_authenticated_ready.has_value());
    CHECK_FALSE(*snapshot.sv2_authenticated_ready);
    CHECK_FALSE(snapshot.sv2_certificate_expiry_timestamp.has_value());

    run_and_stop(server);
}

TEST_CASE("short and oversized SV2 static-secret files disable only authenticated SV2") {
    const auto verify_rejected_size = [](std::size_t secret_size) {
        sv2::test::InitiatorFixture fixture;
        TemporaryNoiseCredentials credentials(fixture);
        credentials.replace_static_secret(secret_size);

        Config config;
        config.bind_host = "127.0.0.1";
        config.bind_port = 0;
        config.sv2_host = "127.0.0.1";
        config.sv2_ports = {0};
        config.sv2_static_secret_key_file = credentials.static_secret();
        config.sv2_authority_public_key_file =
            credentials.authority_public();
        config.sv2_certificate_file = credentials.certificate();
        config.worker_threads = 1;

        UnusedWorkSource source;
        Pool pool(config, source, test::kWorkGeneration);
        net::Server server(pool, config);
        CHECK_NOTHROW(server.start());
        CHECK(server.bound_port(net::WireProtocol::Sv1) != 0);
        CHECK_THROWS_AS(server.bound_port(net::WireProtocol::Sv2Noise),
                        std::logic_error);
        const api::PoolSnapshot snapshot = pool.snapshot();
        REQUIRE(snapshot.sv2_authenticated_ready.has_value());
        CHECK_FALSE(*snapshot.sv2_authenticated_ready);
        CHECK_FALSE(
            snapshot.sv2_certificate_expiry_timestamp.has_value());
        run_and_stop(server);
    };

    verify_rejected_size(SV2_NOISE_SECRET_KEY_SIZE - 1);
    verify_rejected_size(SV2_NOISE_SECRET_KEY_SIZE + 1);
}

TEST_CASE("a failed plaintext SV2 bind rolls back the optional group and leaves SV1 available") {
    const int occupied_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(occupied_fd >= 0);
    FileDescriptor occupied(occupied_fd);
    sockaddr_in occupied_address{};
    occupied_address.sin_family = AF_INET;
    occupied_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    occupied_address.sin_port = 0;
    REQUIRE(::bind(occupied.get(),
                   reinterpret_cast<sockaddr*>(&occupied_address),
                   sizeof(occupied_address)) == 0);
    REQUIRE(::listen(occupied.get(), 1) == 0);
    socklen_t occupied_address_size = sizeof(occupied_address);
    REQUIRE(::getsockname(occupied.get(),
                          reinterpret_cast<sockaddr*>(&occupied_address),
                          &occupied_address_size) == 0);
    const uint16_t occupied_port = ntohs(occupied_address.sin_port);

    Config config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;
    config.sv2_plaintext_host = "127.0.0.1";
    config.sv2_plaintext_ports = {0, occupied_port};
    config.worker_threads = 1;

    UnusedWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    net::Server server(pool, config);
    CHECK_NOTHROW(server.start());
    CHECK(server.bound_port(net::WireProtocol::Sv1) != 0);
    CHECK_THROWS_AS(server.bound_port(net::WireProtocol::Sv2Plaintext),
                    std::logic_error);

    run_and_stop(server);
}

TEST_CASE("authenticated SV2 listener completes Noise before protocol dispatch") {
    sv2::test::InitiatorFixture fixture;
    TemporaryNoiseCredentials credentials(fixture);

    Config config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;
    config.sv2_host = "127.0.0.1";
    config.sv2_ports = {0};
    config.sv2_static_secret_key_file = credentials.static_secret();
    config.sv2_authority_public_key_file = credentials.authority_public();
    config.sv2_certificate_file = credentials.certificate();
    config.worker_threads = 1;
    config.drop_idle_seconds = 0;
    config.auth_timeout_seconds = 0;

    UnusedWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    net::Server server(pool, config);
    server.start();
    const uint16_t port = server.bound_port(net::WireProtocol::Sv2Noise);
    REQUIRE(port != 0);

    std::exception_ptr server_error;
    std::jthread server_thread([&](const std::stop_token& stop) {
        try {
            server.run(stop);
        } catch (...) {
            server_error = std::current_exception();
        }
    });

    FileDescriptor client(::socket(AF_INET, SOCK_STREAM, 0));
    REQUIRE(client.get() >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::connect(client.get(), reinterpret_cast<sockaddr*>(&address),
                      sizeof(address)) == 0);

    send_all(client.get(), fixture.act1());
    const Bytes act2 = receive_exact(client.get(), SV2_NOISE_ACT2_SIZE);
    auto transport = fixture.accept_act2(
        act2, static_cast<uint32_t>(std::time(nullptr)));

    const Bytes setup_request = sv2::encode_message(sv2::SetupConnection{
        sv2::kMiningProtocol,
        sv2::kProtocolVersion,
        sv2::kProtocolVersion,
        sv2::kSetupFlagRequiresStandardJobs,
        "127.0.0.1",
        port,
        "listener-test",
        "test",
        "1",
        "device",
    });
    send_all(client.get(), transport.encrypt_frame(setup_request));

    const Bytes response_shape =
        sv2::encode_message(sv2::SetupConnectionSuccess{0, 0});
    const std::size_t expected_ciphertext_size =
        SV2_NOISE_ENCRYPTED_HEADER_SIZE +
        response_shape.size() - SV2_NOISE_HEADER_SIZE +
        SV2_NOISE_TAG_SIZE;
    const Bytes encrypted_response =
        receive_exact(client.get(), expected_ciphertext_size);
    const Bytes plaintext_response =
        transport.decrypt_flight(encrypted_response);
    sv2::FrameDecoder response_decoder;
    const std::vector<sv2::Frame> response_frames =
        response_decoder.push(plaintext_response);
    REQUIRE(response_frames.size() == 1);
    REQUIRE(response_frames.front().message_type ==
            sv2::SetupConnectionSuccess::kMessageType);
    const auto setup_success =
        sv2::decode_setup_connection_success(response_frames.front().payload);
    CHECK(setup_success.used_version == sv2::kProtocolVersion);

    server_thread.request_stop();
    server_thread.join();
    if (server_error)
        std::rethrow_exception(server_error);
}

TEST_CASE("SV2 listener preserves final frames after the reactor fairness yield") {
    Config config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;
    config.sv2_plaintext_host = "127.0.0.1";
    config.sv2_plaintext_ports = {0};
    config.worker_threads = 1;
    config.drop_idle_seconds = 0;
    config.auth_timeout_seconds = 0;

    UnusedWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    net::Server server(pool, config);
    server.start();
    const uint16_t port = server.bound_port(net::WireProtocol::Sv2Plaintext);
    REQUIRE(port != 0);

    std::exception_ptr server_error;
    std::jthread server_thread([&](const std::stop_token& stop) {
        try {
            server.run(stop);
        } catch (...) {
            server_error = std::current_exception();
        }
    });

    FileDescriptor client(::socket(AF_INET, SOCK_STREAM, 0));
    REQUIRE(client.get() >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::connect(client.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);

    const Bytes ignored_frame =
        sv2::encode_frame({sv2::make_extension_type(1, false), 0xfe, Bytes(64, 0xaa)});
    Bytes request;
    while (request.size() <= kReactorReadBudgetBytes)
        append(request, ignored_frame);
    const std::size_t ignored_bytes = request.size();
    append(request, sv2::encode_message(sv2::SetupConnection{
                        sv2::kMiningProtocol,
                        sv2::kProtocolVersion,
                        sv2::kProtocolVersion,
                        sv2::kSetupFlagRequiresStandardJobs,
                        "127.0.0.1",
                        port,
                        "listener-test",
                        "test",
                        "1",
                        "device",
                    }));
    REQUIRE(ignored_bytes > kReactorReadBudgetBytes);

    send_all(client.get(), request);
    REQUIRE(::shutdown(client.get(), SHUT_WR) == 0);
    const Bytes reply = receive_reply(client.get());

    server_thread.request_stop();
    server_thread.join();
    if (server_error)
        std::rethrow_exception(server_error);

    sv2::FrameDecoder decoder;
    const std::vector<sv2::Frame> frames = decoder.push(reply);
    CHECK_NOTHROW(decoder.finish());
    REQUIRE(frames.size() == 1);
    CHECK(frames.front().extension_type ==
          sv2::make_extension_type(sv2::kCoreExtensionId, false));
    CHECK(frames.front().message_type == sv2::SetupConnectionSuccess::kMessageType);
    const auto success = sv2::decode_setup_connection_success(frames.front().payload);
    CHECK(success.used_version == sv2::kProtocolVersion);
}

TEST_CASE("SV2 listener keeps the connection alive after closing an Extended Channel") {
    Config config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;
    config.sv2_plaintext_host = "127.0.0.1";
    config.sv2_plaintext_ports = {0};
    config.worker_threads = 1;
    config.extranonce1_size = 4;
    config.extranonce2_size = 4;
    config.variable_difficulty = false;
    config.drop_idle_seconds = 0;
    config.auth_timeout_seconds = 0;

    SeededWorkSource source;
    Pool pool(config, source, test::kWorkGeneration);
    pool.detect_network();
    std::jthread refresh_thread(
        [&](const std::stop_token& stop) { pool.refresh_work(stop); });
    REQUIRE(wait_until([&] { return pool.current_job() != nullptr; }));
    refresh_thread.request_stop();
    refresh_thread.join();

    const auto job = pool.current_job();
    REQUIRE(job);
    const auto payout_script = pool.validate_address(std::string(kRegtestAddress));
    REQUIRE(payout_script);
    REQUIRE(pool.validate_address(std::string(kSecondRegtestAddress)));
    const stratum::ExtendedWork expected_work =
        job->build_extended_work(*payout_script);

    Bytes connection_extranonce(config.extranonce1_size);
    util::write_be32(
        connection_extranonce.data(),
        static_cast<uint32_t>(pool.snapshot().starttime + 1));
    Bytes expected_extranonce_prefix_a = connection_extranonce;
    expected_extranonce_prefix_a.push_back(0);
    expected_extranonce_prefix_a.push_back(1);
    Bytes expected_extranonce_prefix_b = connection_extranonce;
    expected_extranonce_prefix_b.push_back(0);
    expected_extranonce_prefix_b.push_back(2);

    net::Server server(pool, config);
    server.start();
    const uint16_t port = server.bound_port(net::WireProtocol::Sv2Plaintext);
    REQUIRE(port != 0);

    std::exception_ptr server_error;
    std::jthread server_thread([&](const std::stop_token& stop) {
        try {
            server.run(stop);
        } catch (...) {
            server_error = std::current_exception();
        }
    });

    FileDescriptor client(::socket(AF_INET, SOCK_STREAM, 0));
    REQUIRE(client.get() >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::connect(client.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);

    sv2::U256 maximum_target{};
    maximum_target.fill(0xff);
    Bytes request = sv2::encode_message(sv2::SetupConnection{
        sv2::kMiningProtocol,
        sv2::kProtocolVersion,
        sv2::kProtocolVersion,
        0,
        "127.0.0.1",
        port,
        "listener-test",
        "test",
        "1",
        "device",
    });
    append(request, sv2::encode_message(sv2::OpenExtendedMiningChannel{
                        7,
                        std::string(kRegtestAddress) + ".a",
                        1'000'000.0F,
                        maximum_target,
                        static_cast<uint16_t>(
                            config.extranonce2_size - kChannelDiscriminatorBytes),
                    }));
    append(request, sv2::encode_message(sv2::OpenExtendedMiningChannel{
                        8,
                        std::string(kSecondRegtestAddress) + ".b",
                        1'000'000.0F,
                        maximum_target,
                        static_cast<uint16_t>(
                            config.extranonce2_size - kChannelDiscriminatorBytes),
                    }));
    send_all(client.get(), request);

    const std::vector<sv2::Frame> frames = receive_frames(client.get(), 7);
    REQUIRE(frames.size() == 7);
    REQUIRE(frames[0].message_type == sv2::SetupConnectionSuccess::kMessageType);
    REQUIRE(frames[1].message_type ==
            sv2::OpenExtendedMiningChannelSuccess::kMessageType);
    REQUIRE(frames[2].message_type == sv2::NewExtendedMiningJob::kMessageType);
    REQUIRE(frames[3].message_type == sv2::SetNewPrevHash::kMessageType);

    const auto setup_success =
        sv2::decode_setup_connection_success(frames[0].payload);
    const auto open_success =
        sv2::decode_open_extended_mining_channel_success(frames[1].payload);
    const auto new_job =
        sv2::decode_new_extended_mining_job(frames[2].payload);
    const auto new_prev_hash =
        sv2::decode_set_new_prev_hash(frames[3].payload);
    REQUIRE(frames[4].message_type ==
            sv2::OpenExtendedMiningChannelSuccess::kMessageType);
    const auto open_success_b =
        sv2::decode_open_extended_mining_channel_success(frames[4].payload);

    CHECK(setup_success.used_version == sv2::kProtocolVersion);
    CHECK(setup_success.flags == 0);
    CHECK(open_success.request_id == 7);
    CHECK(open_success.extranonce_prefix == expected_extranonce_prefix_a);
    CHECK(open_success.extranonce_size ==
          static_cast<uint16_t>(
              config.extranonce2_size - kChannelDiscriminatorBytes));
    CHECK(new_job.channel_id == open_success.channel_id);
    CHECK(new_job.version == job->version());
    CHECK_FALSE(new_job.minimum_ntime.has_value());
    CHECK(new_job.version_rolling_allowed);
    CHECK(new_job.merkle_path == expected_work.merkle_path);
    CHECK(new_job.coinbase_tx_prefix == expected_work.coinbase_tx_prefix);
    CHECK(new_job.coinbase_tx_suffix == expected_work.coinbase_tx_suffix);
    CHECK(new_prev_hash.channel_id == open_success.channel_id);
    CHECK(new_prev_hash.job_id == new_job.job_id);
    CHECK(Bytes(new_prev_hash.previous_hash.begin(), new_prev_hash.previous_hash.end()) ==
          job->prevhash_internal());
    CHECK(new_prev_hash.minimum_ntime == job->curtime());
    CHECK(new_prev_hash.nbits == job->bits());
    CHECK(open_success_b.channel_id == 2);
    CHECK(open_success_b.extranonce_prefix == expected_extranonce_prefix_b);
    REQUIRE(wait_until([&] { return pool.snapshot().connected == 2; }));
    auto snapshot = pool.snapshot();
    CHECK(snapshot.users == 2);
    REQUIRE(snapshot.clients.size() == 2);
    CHECK(snapshot.clients[0].address == kRegtestAddress);
    CHECK(snapshot.clients[0].worker == "a");
    CHECK(snapshot.clients[1].address == kSecondRegtestAddress);
    CHECK(snapshot.clients[1].worker == "b");

    send_all(client.get(), sv2::encode_message(
                               sv2::CloseChannel{open_success.channel_id, "done"}));
    REQUIRE(wait_until([&] { return pool.snapshot().connected == 1; }));
    snapshot = pool.snapshot();
    CHECK(snapshot.users == 1);
    REQUIRE(snapshot.clients.size() == 1);
    CHECK(snapshot.clients[0].address == kSecondRegtestAddress);
    CHECK(snapshot.clients[0].worker == "b");
    CHECK(pool.client_count() == 1);
    send_all(client.get(), sv2::encode_message(
                               sv2::CloseChannel{open_success_b.channel_id, "done"}));
    CHECK(wait_until([&] { return pool.snapshot().connected == 0; }));
    CHECK(pool.client_count() == 1);
    REQUIRE(::shutdown(client.get(), SHUT_WR) == 0);
    CHECK(wait_until([&] { return pool.client_count() == 0; }));

    server_thread.request_stop();
    server_thread.join();
    if (server_error)
        std::rethrow_exception(server_error);
}

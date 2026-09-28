#pragma once
// Pool-specific routes hosted by erikslund-http-embedded.
#include <cstdint>
#include <memory>
#include <stop_token>
#include <string>

namespace erikslund::http {
class Server;
}

namespace erikslund {
class Pool;
}

namespace erikslund::api {

inline constexpr unsigned kMaxConnections = 32;
inline constexpr unsigned kWorkerThreads = 1;

class HttpServer {
public:
    HttpServer(Pool& pool, std::string host, uint16_t port);
    ~HttpServer();
    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;

    void start();
    void run(const std::stop_token& stop);
    [[nodiscard]] uint16_t port() const noexcept;

private:
    std::unique_ptr<http::Server> server_;
};

} // namespace erikslund::api

#include "api/http_server.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "erikslund/http/request.hpp"
#include "erikslund/http/response.hpp"
#include "erikslund/http/router.hpp"
#include "erikslund/http/server.hpp"
#include "erikslund/http/status.hpp"

#include "api/metrics.hpp"
#include "core/logging.hpp"
#include "pool/pool.hpp"

namespace erikslund::api {
namespace {

constexpr std::string_view kAddressCharacters =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
constexpr size_t kMaximumAddressBytes = 127;

namespace http = erikslund::http;

[[nodiscard]] http::Response json_response(std::string body) {
    return http::Response::json(std::move(body)).no_store();
}

[[nodiscard]] http::Response bad_request(std::string body) {
    return http::Response::text(std::move(body), http::Status::BadRequest).no_store();
}

[[nodiscard]] http::Response client_stats_response(const http::Request& request, Pool& pool) {
    const std::string_view address = request.param("address");
    if (address.empty() || address.size() > kMaximumAddressBytes ||
        address.find_first_not_of(kAddressCharacters) != std::string_view::npos)
        return bad_request("invalid address\n");

    const auto body = client_stats_json(pool.snapshot(), std::string(address));
    if (!body)
        return http::Response::text("unknown address\n", http::Status::NotFound).no_store();
    return json_response(to_status_json(*body));
}

[[nodiscard]] http::Router make_router(Pool& pool) {
    http::Router router;
    router.get("/", [&pool](const http::Request&) {
        return http::Response::html(dashboard_html(pool.snapshot())).no_store();
    });
    router.get("/health", [&pool](const http::Request&) {
        return pool.ready()
                   ? http::Response::text("ok\n").no_store()
                   : http::Response::text("degraded\n", http::Status::ServiceUnavailable)
                         .no_store();
    });
    router.get("/healthz", [&pool](const http::Request&) {
        return pool.ready()
                   ? http::Response::text("ok\n").no_store()
                   : http::Response::text("degraded\n", http::Status::ServiceUnavailable)
                         .no_store();
    });
    router.get("/metrics", [&pool](const http::Request&) {
        return http::Response::prometheus(build_prometheus(pool.snapshot())).no_store();
    });
    router.get("/metrics.json", [&pool](const http::Request&) {
        return json_response(to_status_json(metrics_json(pool.snapshot())));
    });
    router.get("/status", [&pool](const http::Request&) {
        return json_response(to_status_json(status_json(pool.snapshot())));
    });
    router.get("/stats/pool", [&pool](const http::Request&) {
        return json_response(to_status_json(pool_stats_json(pool.snapshot())));
    });
    router.get("/stats/stratifier", [&pool](const http::Request&) {
        return json_response(to_status_json(stratifier_stats_json(pool.snapshot())));
    });
    router.get("/stats/connector", [&pool](const http::Request&) {
        return json_response(to_status_json(connector_stats_json(pool.snapshot())));
    });
    router.get("/stats/generator", [&pool](const http::Request&) {
        return json_response(to_status_json(generator_stats_json(pool.snapshot())));
    });
    router.get("/stats/client/", [](const http::Request&) {
        return bad_request("invalid address\n");
    });
    router.get("/stats/client/{address}", [&pool](const http::Request& request) {
        return client_stats_response(request, pool);
    });
    router.get("/favicon.ico", [](const http::Request&) {
        return http::Response::empty(http::Status::NoContent);
    });
    return router;
}

[[nodiscard]] http::LogSink pool_log_sink() {
    return [](http::LogLevel level, std::string_view message) {
        switch (level) {
        case http::LogLevel::Debug:
            log::write(log::Level::Debug, message);
            break;
        case http::LogLevel::Info:
            log::write(log::Level::Info, message);
            break;
        case http::LogLevel::Warning:
            log::write(log::Level::Warning, message);
            break;
        case http::LogLevel::Error:
            log::write(log::Level::Error, message);
            break;
        }
    };
}

[[nodiscard]] http::ServerOptions make_options(std::string host, uint16_t port) {
    http::Listener listener;
    if (!host.empty())
        listener.bind_address = std::move(host);
    listener.port = port;

    http::ServerOptions options;
    options.listeners.push_back(std::move(listener));
    options.worker_threads = kWorkerThreads;
    options.max_connections = kMaxConnections;
    options.limits.max_body_bytes = 0;
    options.reuse_port = false;
    options.log = pool_log_sink();
    return options;
}

} // namespace

HttpServer::HttpServer(Pool& pool, std::string host, uint16_t port)
    : server_(std::make_unique<http::Server>(make_router(pool),
                                             make_options(std::move(host), port))) {}

HttpServer::~HttpServer() = default;

void HttpServer::start() {
    server_->start();
}

void HttpServer::run(const std::stop_token& stop) {
    server_->run(stop);
}

uint16_t HttpServer::port() const noexcept {
    return server_->port();
}

} // namespace erikslund::api

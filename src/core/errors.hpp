#pragma once
// Typed exceptions, all deriving from std::runtime_error.
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace erikslund {

struct ConfigError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// bitcoind returned a JSON-RPC error object.
struct RpcError : std::runtime_error {
    explicit RpcError(std::string message, std::optional<int64_t> code = std::nullopt)
        : std::runtime_error(std::move(message)), code_(code) {}

    std::optional<int64_t> code() const noexcept { return code_; }

private:
    std::optional<int64_t> code_;
};

// The endpoint could not provide a usable RPC response.
struct RpcConnectionError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// The endpoint could not be resolved or connected, before a request was sent.
struct RpcConnectError : RpcConnectionError {
    using RpcConnectionError::RpcConnectionError;
};

} // namespace erikslund

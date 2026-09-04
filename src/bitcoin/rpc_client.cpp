#include "bitcoin/rpc_client.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <exception>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <curl/curl.h>

#include "bitcoin/network.hpp"
#include "core/errors.hpp"
#include "core/logging.hpp"
#include "util/hex.hpp"
#include "util/url.hpp"

namespace erikslund::bitcoin {

namespace {

struct CurlGlobal {
    CurlGlobal() { curl_global_init(CURL_GLOBAL_DEFAULT); }
    ~CurlGlobal() { curl_global_cleanup(); }
};
const CurlGlobal g_curl_global;

constexpr int64_t kRpcClientNotConnected = -9;
constexpr int64_t kRpcClientInInitialDownload = -10;
constexpr int64_t kRpcInWarmup = -28;

std::optional<int64_t> rpc_error_code(const glz::generic& error) {
    if (!error.is_object() || !error.contains("code") || !error["code"].is_number())
        return std::nullopt;
    return static_cast<int64_t>(error["code"].get<double>());
}

bool endpoint_unavailable(const RpcError& error) {
    return error.code() == kRpcClientNotConnected ||
           error.code() == kRpcClientInInitialDownload || error.code() == kRpcInWarmup;
}

std::optional<std::string> submitblock_rejection(const glz::generic& result) {
    if (result.is_null())
        return std::nullopt;
    if (result.is_string())
        return result.get<std::string>();
    return glz::write_json(result).value_or("");
}

std::string base64(std::string_view input) {
    static constexpr char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int value = 0;
    int bits = -6;
    for (unsigned char c : input) {
        value = (value << 8) + c;
        bits += 8;
        while (bits >= 0) {
            out.push_back(table[(value >> bits) & 0x3f]);
            bits -= 6;
        }
    }
    if (bits > -6)
        out.push_back(table[((value << 8) >> (bits + 8)) & 0x3f]);
    while (out.size() % 4 != 0)
        out.push_back('=');
    return out;
}

size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* response = static_cast<std::string*>(userdata);
    response->append(ptr, size * nmemb);
    return size * nmemb;
}

CURL* thread_handle() {
    thread_local std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(nullptr,
                                                                            curl_easy_cleanup);
    if (!handle) {
        CURL* raw = curl_easy_init();
        if (!raw)
            throw RpcConnectionError("failed to initialize curl");
        handle.reset(raw);
    }
    return handle.get();
}

} // namespace

RpcClient::RpcClient(const std::vector<RpcEndpoint>& endpoints, long timeout_seconds)
    : timeout_(std::max(1L, timeout_seconds)),
      connect_timeout_(std::min(timeout_, 5L)),
      poll_timeout_(std::min(timeout_, 10L)) {
    for (const auto& endpoint : endpoints) {
        std::string url = endpoint.url;
        if (url.rfind("http", 0) != 0)
            url.insert(0, "http://");
        endpoints_.push_back(
            {std::move(url), "Authorization: Basic " + base64(endpoint.user + ":" + endpoint.password)});
    }
    if (endpoints_.empty())
        throw std::invalid_argument("RpcClient: no endpoints configured");
}

RpcClient::RpcClient(std::string url, const std::string& user, const std::string& password,
                     long timeout_seconds)
    : RpcClient(std::vector<RpcEndpoint>{{std::move(url), user, password}}, timeout_seconds) {}

std::vector<std::string> RpcClient::endpoint_urls() const {
    std::vector<std::string> urls;
    urls.reserve(endpoints_.size());
    for (const auto& endpoint : endpoints_)
        urls.push_back(endpoint.url);
    return urls;
}

std::string RpcClient::make_payload(const std::string& method, const glz::generic& params) {
    const int id = ++next_id_;
    glz::generic request;
    request["jsonrpc"] = "1.0";
    request["id"] = static_cast<double>(id);
    request["method"] = method;
    request["params"] = params.is_null() ? glz::generic(glz::generic::array_t{}) : params;
    return glz::write_json(request).value_or("");
}

glz::generic RpcClient::call(const std::string& method, const glz::generic& params, long timeout) {
    return call_payload(make_payload(method, params), timeout > 0 ? timeout : timeout_);
}

glz::generic RpcClient::call_payload(const std::string& payload, long timeout) {
    const size_t count = endpoints_.size();
    const size_t start = current_.load();
    std::string last_error;
    for (size_t i = 0; i < count; ++i) {
        const size_t index = (start + i) % count;
        try {
            glz::generic result = call_one(endpoints_[index], payload, timeout);
            if (index != start) {
                size_t expected = start;
                if (current_.compare_exchange_strong(expected, index))
                    log::warning("bitcoind RPC failed over to {}",
                                 util::redact_url(endpoints_[index].url));
            }
            return result;
        } catch (const RpcError& error) {
            if (!endpoint_unavailable(error))
                throw;
            last_error = error.what();
        } catch (const RpcConnectionError& e) {
            last_error = e.what();
        }
    }
    throw RpcConnectionError("all bitcoind endpoints unavailable: " + last_error);
}

std::string RpcClient::post_one(const Resolved& endpoint, const std::string& payload, long timeout,
                                long* http_status) {
    CURL* curl = thread_handle();
    curl_easy_reset(curl);

    std::string response;
    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, endpoint.auth_header.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, endpoint.url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(payload.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout_);
    // Multi-threaded: the resolver's timeout SIGALRM/siglongjmp isn't thread-safe.
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    const CURLcode curl_result = curl_easy_perform(curl);
    if (http_status)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_status);
    curl_slist_free_all(headers);

    if (curl_result != CURLE_OK)
        throw RpcConnectionError(std::string("transport error: ") + curl_easy_strerror(curl_result));
    return response;
}

glz::generic RpcClient::call_one(const Resolved& endpoint, const std::string& payload,
                                 long timeout) {
    long http_status = 0;
    const std::string response = post_one(endpoint, payload, timeout, &http_status);
    glz::generic parsed;
    if (glz::read_json(parsed, response))
        // Keep the HTTP code so a 401 (bad RPC creds) stays distinguishable from garbage.
        throw RpcConnectionError("unparseable body (HTTP " + std::to_string(http_status) + ")");
    if (parsed.contains("error") && !parsed["error"].is_null()) {
        const glz::generic& error = parsed["error"];
        throw RpcError(glz::write_json(error).value_or("rpc error"), rpc_error_code(error));
    }
    if (!parsed.contains("result"))
        throw RpcConnectionError("reply has no result (HTTP " + std::to_string(http_status) + ")");
    // Move the result subtree out; a copy would duplicate the whole DOM.
    return std::move(parsed["result"]);
}

std::string RpcClient::make_getblocktemplate_payload() {
    glz::generic request;
    request["rules"] = glz::generic::array_t{"segwit"};
    request["capabilities"] = glz::generic::array_t{"coinbasetxn", "workid", "coinbase/append"};
    return make_payload("getblocktemplate", glz::generic::array_t{request});
}

BlockTemplate RpcClient::fetch_template_from(size_t index, const std::string& payload,
                                            std::string& response_body) {
    long http_status = 0;
    response_body = post_one(endpoints_[index], payload, poll_timeout_, &http_status);
    try {
        return BlockTemplate::from_gbt(response_body);
    } catch (const std::invalid_argument& error) {
        throw RpcConnectionError("unparseable body (HTTP " + std::to_string(http_status) +
                                 "): " + error.what());
    }
}

BlockTemplate RpcClient::getblocktemplate_parsed() {
    if (auto failback_template = try_fetch_failback_template())
        return std::move(*failback_template);

    const std::string payload = make_getblocktemplate_payload();
    const size_t count = endpoints_.size();
    const size_t start = current_.load();
    std::string last_error;

    for (size_t offset = 0; offset < count; ++offset) {
        const size_t index = (start + offset) % count;
        BlockTemplate block_template;
        try {
            block_template = fetch_template_from(index, payload, gbt_body_);
        } catch (const RpcError& error) {
            if (!endpoint_unavailable(error))
                throw;
            last_error = error.what();
            continue;
        } catch (const RpcConnectionError& e) {
            last_error = e.what();
            continue;
        }
        // Only now is this endpoint proven to be serving work.
        if (index != start) {
            size_t expected = start;
            if (current_.compare_exchange_strong(expected, index))
                log::warning("bitcoind RPC failed over to {}",
                             util::redact_url(endpoints_[index].url));
        }
        return block_template;
    }
    throw RpcConnectionError("all bitcoind endpoints unavailable for mining work: " + last_error);
}

std::optional<std::string> RpcClient::submitblock(const std::string& block_hex) {
    const int id = ++next_id_;
    std::string payload;
    payload.reserve(block_hex.size() + 96);
    payload += "{\"jsonrpc\":\"1.0\",\"id\":";
    payload += std::to_string(id);
    payload += ",\"method\":\"submitblock\",\"params\":[\"";
    payload += block_hex;
    payload += "\"]}";

    std::vector<std::future<glz::generic>> responses;
    responses.reserve(endpoints_.size());
    for (size_t index = 0; index < endpoints_.size(); ++index) {
        responses.push_back(std::async(std::launch::async, [this, index, &payload] {
            return call_one(endpoints_[index], payload, timeout_);
        }));
    }

    bool accepted = false;
    bool already_known = false;
    std::optional<std::string> inconclusive;
    std::optional<std::string> first_rejection;
    std::exception_ptr first_error;
    for (auto& response : responses) {
        try {
            const auto rejection = submitblock_rejection(response.get());
            if (!rejection) {
                accepted = true;
            } else if (*rejection == "duplicate") {
                already_known = true;
            } else if (*rejection == "inconclusive" || *rejection == "duplicate-inconclusive") {
                if (!inconclusive)
                    inconclusive = rejection;
            } else if (!first_rejection) {
                first_rejection = rejection;
            }
        } catch (...) {
            if (!first_error)
                first_error = std::current_exception();
        }
    }

    // Submission must not change which endpoint supplies mining work.
    if (accepted)
        return std::nullopt;
    if (already_known)
        return "duplicate";
    if (inconclusive)
        return inconclusive;
    if (first_error)
        std::rethrow_exception(first_error);
    if (first_rejection)
        return first_rejection;
    throw RpcConnectionError("submitblock received no endpoint response");
}

glz::generic RpcClient::validateaddress(const std::string& address) {
    glz::generic params = glz::generic::array_t{address};
    return call("validateaddress", params);
}

std::string RpcClient::getbestblockhash() {
    return call("getbestblockhash", glz::generic{}, poll_timeout_).get<std::string>();
}

MiningTip RpcClient::get_mining_tip() {
    const Resolved& endpoint = endpoints_[current_.load()];
    const auto info = call_one(endpoint, make_payload("getblockchaininfo"), poll_timeout_);
    if (!info.is_object() || !info.contains("chain") || !info["chain"].is_string() ||
        !info.contains("blocks") || !info["blocks"].is_number() ||
        !info.contains("bestblockhash") || !info["bestblockhash"].is_string())
        throw RpcConnectionError("getblockchaininfo returned an invalid mining tip");

    const auto network = network_from_string(info["chain"].get<std::string>());
    const double height = info["blocks"].get<double>();
    const auto& hash = info["bestblockhash"].get<std::string>();
    if (!network || height < 0 || height > std::numeric_limits<int32_t>::max() ||
        std::trunc(height) != height || hash.size() != 64 || !util::is_hex(hash))
        throw RpcConnectionError("getblockchaininfo returned an invalid mining tip");

    // Bitcoin Core's getblocktemplate exempts test chains from these readiness checks.
    if (*network == Network::Mainnet) {
        if (!info.contains("initialblockdownload") || !info["initialblockdownload"].is_boolean())
            throw RpcConnectionError("getblockchaininfo omitted initialblockdownload");
        if (info["initialblockdownload"].get<bool>())
            throw RpcError("Bitcoin Core is in initial block download", kRpcClientInInitialDownload);
        const auto connections =
            call_one(endpoint, make_payload("getconnectioncount"), poll_timeout_);
        if (!connections.is_number() || connections.get<double>() < 1)
            throw RpcError("Bitcoin Core is not connected", kRpcClientNotConnected);
    }
    return {hash, static_cast<int64_t>(height)};
}

void RpcClient::maybe_failback(const std::string& expected_tip) {
    if (current_.load() == 0 || expected_tip.empty())
        return; // already on primary / no tip to compare against
    const double now =
        std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
    if (now - last_failback_probe_.load() < kFailbackProbeSeconds)
        return;
    last_failback_probe_.store(now);
    const std::string payload = make_payload("getbestblockhash");
    try {
        const auto result = call_one(endpoints_[0], payload, poll_timeout_);
        if (!result.is_string() || result.get<std::string>() != expected_tip)
            return;
        // The status thread probes recovery without blocking work from the active node.
        std::string response_body;
        auto block_template =
            fetch_template_from(0, make_getblocktemplate_payload(), response_body);
        if (block_template.previousblockhash != expected_tip)
            return;
        const std::scoped_lock lock(failback_mutex_);
        failback_template_ = std::move(block_template);
    } catch (const std::exception&) {
        return;
    }
}

std::optional<BlockTemplate> RpcClient::try_fetch_failback_template() {
    std::optional<BlockTemplate> block_template;
    {
        const std::scoped_lock lock(failback_mutex_);
        block_template = std::exchange(failback_template_, std::nullopt);
    }
    if (!block_template || current_.load() == 0)
        return std::nullopt;

    try {
        // A new tip may have arrived while the candidate waited for the next refresh.
        if (block_template->previousblockhash != getbestblockhash())
            return std::nullopt;
        if (current_.exchange(0) != 0)
            log::info("bitcoind RPC failed back to the primary {}",
                      util::redact_url(endpoints_[0].url));
        return block_template;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

glz::generic RpcClient::getblockheader(const std::string& block_hash) {
    glz::generic params = glz::generic::array_t{block_hash};
    return call("getblockheader", params);
}

glz::generic RpcClient::getblockchaininfo() {
    return call("getblockchaininfo");
}

} // namespace erikslund::bitcoin

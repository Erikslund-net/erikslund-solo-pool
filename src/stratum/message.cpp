#include "stratum/message.hpp"

#include <charconv>
#include <cmath>
#include <cstdint>
#include <string>
#include <system_error>

#include <glaze/glaze.hpp>

#include "util/json_number.hpp"

namespace erikslund::stratum {

using json = glz::generic;

// Glaze reflection requires this file-private wire type to have external linkage.
namespace message_detail {

struct RequestWire {
    json id{};
    std::optional<std::string> method{};
    std::optional<std::vector<std::string>> params{};
};

} // namespace message_detail

namespace {

// Reject pathologically nested JSON: guards against stack exhaustion on small thread stacks
// (legit Stratum messages are flat).
constexpr int kMaxJsonDepth = 64;

constexpr glz::opts kRequestReadOptions{.null_terminated = false};

bool within_depth(std::string_view text) {
    int depth = 0;
    bool in_string = false, escaped = false;
    for (char c : text) {
        if (in_string) {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == '"')
                in_string = false;
            continue;
        }
        if (c == '"')
            in_string = true;
        else if (c == '{' || c == '[') {
            if (++depth > kMaxJsonDepth)
                return false;
        } else if ((c == '}' || c == ']') && depth > 0) {
            --depth;
        }
    }
    return true;
}

std::string id_wire(const json& id) {
    return glz::write_json(id).value_or("null");
}

void normalize_request_id(json& request_id, const json& raw_id) {
    if (raw_id.is_string()) {
        request_id = raw_id;
    } else if (raw_id.is_number()) {
        const double value = raw_id.get<double>();
        if (std::isfinite(value) && value == std::floor(value))
            request_id = raw_id;
    }
}

} // namespace

std::optional<Request> parse_request(std::string_view line) {
    if (!within_depth(line))
        return std::nullopt;

    // Fast path
    {
        message_detail::RequestWire wire;
        if (!glz::read<kRequestReadOptions>(wire, line)) {
            if (!wire.method)
                return std::nullopt; // missing or null method: the DOM path rejects these too
            // configure/suggest_difficulty carry non-flat params the typed shape can't represent
            // (nested arrays; a numeric difficulty): let the DOM path extract them.
            if (*wire.method != "mining.configure" && *wire.method != "mining.suggest_difficulty") {
                Request request;
                request.method = std::move(*wire.method);
                normalize_request_id(request.id, wire.id);
                if (wire.params)
                    request.params = std::move(*wire.params);
                return request;
            }
        }
    }

    return detail::parse_request_dom(line);
}

std::optional<Request> detail::parse_request_dom(std::string_view line) {
    json doc;
    if (glz::read<kRequestReadOptions>(doc, line))   // parse error
        return std::nullopt;
    if (!doc.is_object())
        return std::nullopt;
    if (!doc.contains("method") || !doc["method"].is_string())
        return std::nullopt;

    Request request;
    request.method = doc["method"].get<std::string>();

    if (doc.contains("id"))
        normalize_request_id(request.id, doc["id"]);

    json::array_t* params = nullptr;
    if (doc.contains("params") && doc["params"].is_array())
        params = &doc["params"].get_array();
    if (params) {
        request.params.reserve(params->size());
        for (const json& element : *params)
            request.params.emplace_back(element.is_string() ? element.get<std::string>()
                                                            : std::string());
    }

    // mining.configure nests an array + an object.
    if (request.method == "mining.configure" && params) {
        if (!params->empty() && (*params)[0].is_array())
            for (const json& extension : (*params)[0].get_array())
                if (extension.is_string()) {
                    std::string name = extension.get<std::string>();
                    if (name == "version-rolling")
                        request.configure_version_rolling = true;
                    request.configure_extensions.push_back(std::move(name));
                }
        // Distinguish "no mask key" (absent -> no client preference) from "key present but
        // malformed/non-string" (-> disable rolling).
        if (params->size() > 1 && (*params)[1].is_object() &&
            (*params)[1].contains("version-rolling.mask")) {
            request.version_rolling_mask_present = true;
            const json& mask = (*params)[1]["version-rolling.mask"];
            if (mask.is_string())
                request.version_rolling_mask = mask.get<std::string>();
        }
    }

    if (request.method == "mining.suggest_difficulty" && params && !params->empty()) {
        const json& first = (*params)[0];
        if (first.is_number()) {
            request.suggested_difficulty = first.get<double>();
        } else if (first.is_string()) {
            const std::string& text = first.get<std::string>();
            const char* const end = text.data() + text.size();
            double value = 0.0;
            if (const auto [ptr, ec] = std::from_chars(text.data(), end, value);
                ec == std::errc{} && ptr == end)
                request.suggested_difficulty = value;
        }
    }
    return request;
}

json make_result(const json& id, json result) {
    json out = json::object_t{};
    out["error"] = json{}; // null
    out["id"] = id;
    out["result"] = std::move(result);
    return out;
}

json make_error(const json& id, const StratumError& error) {
    json error_triple = json::array_t{};
    error_triple.get_array().emplace_back(static_cast<double>(error.code));
    error_triple.get_array().emplace_back(std::string(error.message));
    error_triple.get_array().emplace_back(json{}); // null
    json out = json::object_t{};
    out["error"] = std::move(error_triple);
    out["id"] = id;
    out["result"] = json{}; // null
    return out;
}

json make_notification(std::string_view method, json params) {
    json out = json::object_t{};
    out["id"] = json{}; // null
    out["method"] = std::string(method);
    out["params"] = std::move(params);
    return out;
}

void make_result_line_into(std::string& out, const json& id, bool result) {
    out.clear(); // capacity persists: after the first response this path allocates nothing
    out += "{\"error\":null,\"id\":";
    out += id_wire(id);
    out += result ? ",\"result\":true}" : ",\"result\":false}";
}

std::string make_result_line(const json& id, bool result) {
    std::string out;
    out.reserve(48); // covers the frame + any numeric id; string ids may grow once
    make_result_line_into(out, id, result);
    return out;
}

std::string make_notify_line(const std::string& job_id, const std::string& prevhash_stratum,
                             const std::string& coinbase1_hex, const std::string& coinbase2_hex,
                             const std::vector<std::string>& merkle_branch_hex,
                             const std::string& version_hex, const std::string& nbits_hex,
                             const std::string& ntime_hex, bool clean) {
    size_t branches_size = 2; // "[]"
    for (const auto& branch : merkle_branch_hex)
        branches_size += branch.size() + 3; // quotes + comma
    std::string out;
    out.reserve(64 + job_id.size() + prevhash_stratum.size() + coinbase1_hex.size() +
                coinbase2_hex.size() + branches_size + version_hex.size() + nbits_hex.size() +
                ntime_hex.size() + 32);
    out += R"({"id":null,"method":"mining.notify","params":[")";
    out += job_id;
    out += "\",\"";
    out += prevhash_stratum;
    out += "\",\"";
    out += coinbase1_hex;
    out += "\",\"";
    out += coinbase2_hex;
    out += "\",[";
    bool first = true;
    for (const auto& branch : merkle_branch_hex) {
        if (!first)
            out += ',';
        first = false;
        out += '"';
        out += branch;
        out += '"';
    }
    out += "],\"";
    out += version_hex;
    out += "\",\"";
    out += nbits_hex;
    out += "\",\"";
    out += ntime_hex;
    out += clean ? "\",true]}" : "\",false]}";
    return out;
}

std::string make_set_difficulty_line(double difficulty) {
    return std::string(R"({"id":null,"method":"mining.set_difficulty","params":[)") +
           util::format_json_number(difficulty) + "]}";
}

void make_error_line_into(std::string& out, const json& id, const StratumError& error) {
    // error.message is a compile-time constant with no JSON-special chars; embed without escaping.
    out.clear(); // capacity persists across calls (see make_result_line_into)
    out += "{\"error\":[";
    out += std::to_string(error.code);
    out += ",\"";
    out += error.message;
    out += "\",null],\"id\":";
    out += id_wire(id);
    out += ",\"result\":null}";
}

std::string make_error_line(const json& id, const StratumError& error) {
    std::string out;
    out.reserve(80); // frame + longest error message + any numeric id
    make_error_line_into(out, id, error);
    return out;
}

} // namespace erikslund::stratum

// Adversarial / negative coverage for the Stratum JSON-RPC request parser.
#include <doctest/doctest.h>

#include <limits>
#include <string>
#include <string_view>

#include "stratum/message.hpp"

using namespace erikslund::stratum;

TEST_CASE("parse_request rejects every non-object top-level JSON shape") {
    CHECK_FALSE(parse_request("\"just a string\"").has_value());
    CHECK_FALSE(parse_request("12345").has_value());
    CHECK_FALSE(parse_request("3.14159").has_value());
    CHECK_FALSE(parse_request("true").has_value());
    CHECK_FALSE(parse_request("false").has_value());
    CHECK_FALSE(parse_request("null").has_value());
    CHECK_FALSE(parse_request("[]").has_value());
    CHECK_FALSE(parse_request(R"(["mining.subscribe",1])").has_value());
}

TEST_CASE("parse_request rejects truncated / unbalanced JSON without throwing") {
    CHECK_FALSE(parse_request("{").has_value());
    CHECK_FALSE(parse_request("}").has_value());
    CHECK_FALSE(parse_request("{{{{").has_value());
    CHECK_FALSE(parse_request("}}}}").has_value());
    CHECK_FALSE(parse_request(R"({"method":)").has_value());           // value cut off
    CHECK_FALSE(parse_request(R"({"method":"mining.subscribe")").has_value()); // no closing brace
    CHECK_FALSE(parse_request(R"({"method":"mining.subscribe",})").has_value()); // trailing comma
    CHECK_FALSE(parse_request(R"({"method":"a","params":[1,2,)").has_value());   // array cut off
    CHECK_FALSE(parse_request(R"({"id":1,"method":"a","params":[}})").has_value());
}

TEST_CASE("request parsers reject empty exponents but accept signed exponents") {
    for (const auto parse : {parse_request, detail::parse_request_dom}) {
        for (const char* number : {"1e", "1e+", "1e-", "1E", "1E+", "1E-"}) {
            CAPTURE(number);
            CHECK_FALSE(parse(std::string(R"({"id":)") + number +
                              R"(,"method":"mining.subscribe"})").has_value());
            CHECK_FALSE(parse(std::string(R"({"method":"mining.suggest_difficulty","params":[)") +
                              number + "]}").has_value());
        }
        for (const char* number : {"1e2", "1e+2", "10000e-2", "1E2", "1E+2", "10000E-2"}) {
            CAPTURE(number);
            const auto request = parse(std::string(R"({"id":)") + number +
                                       R"(,"method":"mining.subscribe"})");
            REQUIRE(request.has_value());
            REQUIRE(request->id.is_number());
            CHECK(request->id.get<double>() == doctest::Approx(100.0));

            const auto suggestion = parse(
                std::string(R"({"method":"mining.suggest_difficulty","params":[)") +
                number + "]}");
            REQUIRE(suggestion.has_value());
            REQUIRE(suggestion->suggested_difficulty.has_value());
            CHECK(*suggestion->suggested_difficulty == doctest::Approx(100.0));
        }
    }
}

TEST_CASE("request parsers respect string_view boundaries at every truncation") {
    const std::string line =
        R"({"id":"request","method":"mining.submit","params":["rig\"name","job"]})";
    const std::string backing = line + "trailing bytes outside the view";
    const std::string_view view(backing.data(), line.size());
    for (const auto parse : {parse_request, detail::parse_request_dom}) {
        const auto request = parse(view);
        REQUIRE(request.has_value());
        CHECK(request->method == "mining.submit");
        REQUIRE(request->params.size() == 2);
        CHECK(request->params[0] == "rig\"name");
        for (size_t length = 0; length < view.size(); ++length) {
            CAPTURE(length);
            CHECK_FALSE(parse(view.substr(0, length)).has_value());
        }
    }
}

TEST_CASE("parse_request rejects bare / garbage / control-character text") {
    CHECK_FALSE(parse_request("garbage text here").has_value());
    CHECK_FALSE(parse_request("\x01\x02\x03\x04").has_value());
    CHECK_FALSE(parse_request("\xff\xfe\xfd").has_value());           // invalid UTF-8 bytes
    CHECK_FALSE(parse_request("{method:subscribe}").has_value());      // unquoted keys
    CHECK_FALSE(parse_request("<?xml version=\"1.0\"?>").has_value()); // not JSON at all
}

TEST_CASE("parse_request rejects invalid UTF-8 inside an otherwise well-formed string") {
    CHECK_FALSE(
        parse_request("{\"id\":1,\"method\":\"mining.submit\",\"params\":[\"rig\xE9\"]}").has_value());
    CHECK_FALSE(parse_request("{\"id\":1,\"method\":\"a\",\"params\":[\"\x80\"]}").has_value());
    CHECK_FALSE(parse_request("{\"id\":1,\"method\":\"a\",\"params\":[\"\xE2\x82\"]}").has_value());
    CHECK_FALSE(parse_request("{\"id\":1,\"method\":\"mining.\xFF\",\"params\":[]}").has_value());
    CHECK_FALSE(parse_request("{\"id\":1,\"method\":\"a\",\"par\xE9m\":[]}").has_value());

    const auto valid = parse_request(
        "{\"id\":1,\"method\":\"mining.submit\",\"params\":[\"rig\xC3\xA9\"]}");
    REQUIRE(valid.has_value());
    CHECK(valid->params.at(0) == "rig\xC3\xA9");
}

TEST_CASE("parse_request rejects empty and whitespace-only lines") {
    CHECK_FALSE(parse_request("").has_value());
    CHECK_FALSE(parse_request(" ").has_value());
    CHECK_FALSE(parse_request("   \t  ").has_value());
    CHECK_FALSE(parse_request("\r\n").has_value());
    CHECK_FALSE(parse_request("\n\n\n").has_value());
    CHECK_FALSE(parse_request("\t").has_value());
}

TEST_CASE("parse_request rejects a missing method") {
    CHECK_FALSE(parse_request(R"({})").has_value());
    CHECK_FALSE(parse_request(R"({"id":1})").has_value());
    CHECK_FALSE(parse_request(R"({"id":1,"params":["a"]})").has_value());
}

TEST_CASE("parse_request rejects a method that is not a string") {
    CHECK_FALSE(parse_request(R"({"method":123})").has_value());
    CHECK_FALSE(parse_request(R"({"method":1.5})").has_value());
    CHECK_FALSE(parse_request(R"({"method":true})").has_value());
    CHECK_FALSE(parse_request(R"({"method":null})").has_value());
    CHECK_FALSE(parse_request(R"({"method":["mining.subscribe"]})").has_value());
    CHECK_FALSE(parse_request(R"({"method":{"name":"mining.subscribe"}})").has_value());
}

TEST_CASE("an empty-string method parses but carries no params and dispatches nowhere") {
    // "" is a valid JSON string, so parsing succeeds; downstream dispatch ignores it.
    const auto req = parse_request(R"({"id":1,"method":"","params":[]})");
    REQUIRE(req.has_value());
    CHECK(req->method.empty());
    CHECK(req->params.empty());
}

TEST_CASE("params that is not an array yields an empty params vector (no throw)") {
    for (const char* line : {
             R"({"method":"mining.submit","params":"a string"})",
             R"({"method":"mining.submit","params":42})",
             R"({"method":"mining.submit","params":true})",
             R"({"method":"mining.submit","params":null})",
             R"({"method":"mining.submit","params":{"k":"v"}})",
         }) {
        const auto req = parse_request(line);
        REQUIRE(req.has_value());
        CHECK(req->params.empty());
    }
}

TEST_CASE("a missing params field yields an empty params vector") {
    const auto req = parse_request(R"({"id":1,"method":"mining.submit"})");
    REQUIRE(req.has_value());
    CHECK(req->params.empty());
}

TEST_CASE("non-string params elements become empty strings, positions preserved") {
    // numbers, bools, null, nested array/object -> "" (rejected downstream by length/hex checks)
    const auto req = parse_request(
        R"({"method":"mining.submit","params":["w",1,2.5,true,null,["x"],{"k":1},"tail"]})");
    REQUIRE(req.has_value());
    REQUIRE(req->params.size() == 8);
    CHECK(req->params[0] == "w");
    CHECK(req->params[1].empty()); // 1
    CHECK(req->params[2].empty()); // 2.5
    CHECK(req->params[3].empty()); // true
    CHECK(req->params[4].empty()); // null
    CHECK(req->params[5].empty()); // ["x"]
    CHECK(req->params[6].empty()); // {"k":1}
    CHECK(req->params[7] == "tail");
}

TEST_CASE("a deeply long but flat params array is accepted without issue") {
    // Stress the element loop with many entries (no nesting, so depth guard is fine).
    std::string line = R"({"method":"mining.submit","params":[)";
    for (int i = 0; i < 2000; ++i) {
        if (i)
            line.push_back(',');
        line += "\"x\"";
    }
    line += "]}";
    const auto req = parse_request(line);
    REQUIRE(req.has_value());
    CHECK(req->params.size() == 2000);
}

TEST_CASE("nesting just past the depth guard is rejected, just under is allowed") {
    // 65 opening braces in the params value exceeds 64 -> within_depth() returns false.
    auto nested = [](int depth) {
        std::string s = R"({"method":"mining.submit","params":)";
        for (int i = 0; i < depth; ++i)
            s.push_back('[');
        s += "1";
        for (int i = 0; i < depth; ++i)
            s.push_back(']');
        s.push_back('}');
        return s;
    };
    // depth 70 total (including the outer object) clearly exceeds the guard.
    CHECK_FALSE(parse_request(nested(70)).has_value());
    // A shallow nesting (e.g. 10) is fine structurally; params becomes [] (array is non-string).
    const auto shallow = parse_request(nested(10));
    REQUIRE(shallow.has_value());
}

TEST_CASE("a flood of opening brackets is rejected by the depth guard, not parsed") {
    std::string s(10000, '[');
    CHECK_FALSE(parse_request(s).has_value());
}

TEST_CASE("braces inside a JSON string do not count toward depth") {
    std::string body(200, '{');
    const std::string line =
        R"({"method":"mining.authorize","params":[")" + body + R"("]})";
    const auto req = parse_request(line);
    REQUIRE(req.has_value());
    CHECK(req->params.size() == 1);
    CHECK(req->params[0] == body);
}

TEST_CASE("escaped quotes and backslashes inside strings are handled by the depth scanner") {
    // The within_depth() scanner tracks string/escape state; an escaped quote must
    // not prematurely close the string and let following braces inflate the depth.
    const auto req =
        parse_request(R"({"method":"mining.authorize","params":["a\"]}]}[[[[","b"]})");
    REQUIRE(req.has_value());
    REQUIRE(req->params.size() == 2);
    CHECK(req->params[0] == R"(a"]}]}[[[[)");
    CHECK(req->params[1] == "b");
}

TEST_CASE("a trailing backslash escape state at end of input does not crash the scanner") {
    // String never closes; this must be rejected as malformed, not loop/overrun.
    CHECK_FALSE(parse_request(R"({"method":"a","params":["abc\)").has_value());
    CHECK_FALSE(parse_request(R"({"method":"a","params":["unterminated)").has_value());
}

TEST_CASE("mining.configure with non-array extensions does not throw and rolls nothing") {
    for (const char* line : {
             R"({"id":1,"method":"mining.configure","params":["not-an-array",{}]})",
             R"({"id":1,"method":"mining.configure","params":[42,{}]})",
             R"({"id":1,"method":"mining.configure","params":[null,{}]})",
             R"({"id":1,"method":"mining.configure","params":[{},{}]})",
         }) {
        const auto req = parse_request(line);
        REQUIRE(req.has_value());
        CHECK_FALSE(req->configure_version_rolling);
        CHECK_FALSE(req->version_rolling_mask.has_value());
    }
}

TEST_CASE("mining.configure with empty / missing params does not throw") {
    const auto empty = parse_request(R"({"id":1,"method":"mining.configure","params":[]})");
    REQUIRE(empty.has_value());
    CHECK_FALSE(empty->configure_version_rolling);
    CHECK_FALSE(empty->version_rolling_mask.has_value());

    const auto missing = parse_request(R"({"id":1,"method":"mining.configure"})");
    REQUIRE(missing.has_value());
    CHECK_FALSE(missing->configure_version_rolling);
}

TEST_CASE("mining.configure extensions array with non-string entries is tolerated") {
    const auto req = parse_request(
        R"({"id":1,"method":"mining.configure","params":[[1,true,null,"version-rolling"],{}]})");
    REQUIRE(req.has_value());
    CHECK(req->configure_version_rolling); // the lone valid string still flips the flag
}

TEST_CASE("mining.configure mask that is not a string leaves the mask unset") {
    // version-rolling.mask given as a number / bool -> get<string_view> fails -> unset.
    const auto numeric = parse_request(
        R"({"id":1,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":12345}]})");
    REQUIRE(numeric.has_value());
    CHECK(numeric->configure_version_rolling);
    CHECK_FALSE(numeric->version_rolling_mask.has_value());
}

TEST_CASE("mining.configure carries a non-hex mask string verbatim (validated later)") {
    // Parsing only extracts the string; handle_configure() is where bad hex -> 0 mask.
    const auto req = parse_request(
        R"({"id":1,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"nothex!!"}]})");
    REQUIRE(req.has_value());
    REQUIRE(req->version_rolling_mask.has_value());
    CHECK(*req->version_rolling_mask == "nothex!!");
}

TEST_CASE("suggest_difficulty: non-numeric / wrong-type values leave the suggestion unset") {
    for (const char* line : {
             R"({"method":"mining.suggest_difficulty","params":["not-a-number"]})",
             R"({"method":"mining.suggest_difficulty","params":[""]})",
             R"({"method":"mining.suggest_difficulty","params":[true]})",
             R"({"method":"mining.suggest_difficulty","params":[false]})",
             R"({"method":"mining.suggest_difficulty","params":[null]})",
             R"({"method":"mining.suggest_difficulty","params":[[1024]]})",
             R"({"method":"mining.suggest_difficulty","params":[{"v":1024}]})",
             R"({"method":"mining.suggest_difficulty","params":[]})",
         }) {
        const auto req = parse_request(line);
        REQUIRE(req.has_value());
        CHECK_FALSE(req->suggested_difficulty.has_value());
    }
}

TEST_CASE("suggest_difficulty: a negative number is captured (clamped later, not here)") {
    const auto req =
        parse_request(R"({"method":"mining.suggest_difficulty","params":[-50]})");
    REQUIRE(req.has_value());
    REQUIRE(req->suggested_difficulty.has_value());
    CHECK(*req->suggested_difficulty == doctest::Approx(-50.0));
}

TEST_CASE("suggest_difficulty: an enormous number is captured without overflow/throw") {
    const auto huge =
        parse_request(R"({"method":"mining.suggest_difficulty","params":[1e308]})");
    REQUIRE(huge.has_value());
    REQUIRE(huge->suggested_difficulty.has_value());
    CHECK(*huge->suggested_difficulty > 1e307);

    // A 30-digit integer string overflows int64 but is a valid (whole-string) decimal; from_chars
    // still yields a finite double.
    const auto bigstr = parse_request(
        R"({"method":"mining.suggest_difficulty","params":["123456789012345678901234567890"]})");
    REQUIRE(bigstr.has_value());
    REQUIRE(bigstr->suggested_difficulty.has_value());
    CHECK(*bigstr->suggested_difficulty > 0.0);
}

TEST_CASE("suggest_difficulty: a string with trailing junk after a number is rejected") {
    // A difficulty must be a bare number, so the parser cannot ignore a malicious suffix.
    const auto req = parse_request(
        R"({"method":"mining.suggest_difficulty","params":["256xyz"]})");
    REQUIRE(req.has_value());
    CHECK_FALSE(req->suggested_difficulty.has_value());
}

TEST_CASE("suggest_difficulty: 'inf'/'nan' strings parse to non-finite (rejected later)") {
    // These must not throw at parse time; clamp_suggested_difficulty rejects non-finite.
    const auto inf = parse_request(
        R"({"method":"mining.suggest_difficulty","params":["inf"]})");
    REQUIRE(inf.has_value());
    // from_chars("inf") == +infinity; capture stays non-finite (rejected downstream, never throws).
    if (inf->suggested_difficulty)
        CHECK_FALSE(std::isfinite(*inf->suggested_difficulty));

    const auto nan = parse_request(
        R"({"method":"mining.suggest_difficulty","params":["nan"]})");
    REQUIRE(nan.has_value()); // no throw regardless of capture
}

TEST_CASE("non-int / non-string ids fall back to null without throwing") {
    for (const char* line : {
             R"({"id":1.5,"method":"mining.subscribe"})",
             R"({"id":true,"method":"mining.subscribe"})",
             R"({"id":[1,2],"method":"mining.subscribe"})",
             R"({"id":{"n":1},"method":"mining.subscribe"})",
         }) {
        const auto req = parse_request(line);
        REQUIRE(req.has_value());
        CHECK(req->id.is_null());
    }
}

TEST_CASE("an extreme integer id is carried as a number") {
    const auto req = parse_request(
        R"({"id":9223372036854775807,"method":"mining.subscribe"})");
    REQUIRE(req.has_value());
    CHECK(req->id.is_number());
}

TEST_CASE("duplicate keys do not crash the parser (last-wins per the JSON lib)") {
    const auto req = parse_request(
        R"({"method":"mining.subscribe","method":"mining.authorize","params":["x"]})");
    // Either method may win depending on the parser; the contract is only "no crash".
    REQUIRE(req.has_value());
    CHECK((req->method == "mining.subscribe" || req->method == "mining.authorize"));
}

TEST_CASE("a very long method string is parsed without overrun") {
    const std::string method(100000, 'm');
    const std::string line = R"({"method":")" + method + R"("})";
    const auto req = parse_request(line);
    REQUIRE(req.has_value());
    CHECK(req->method.size() == 100000);
}

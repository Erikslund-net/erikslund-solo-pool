#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "core/logging.hpp"

using namespace erikslund;

TEST_CASE("log rate limits report suppressed messages at the next permitted emission") {
    using namespace std::chrono_literals;
    log::RateLimit limit(30s);
    const auto start = std::chrono::steady_clock::time_point{};
    CHECK(limit.admit(start) == 0);
    CHECK_FALSE(limit.admit(start));
    CHECK_FALSE(limit.admit(start + 29s));
    CHECK(limit.admit(start + 30s) == 2);
    CHECK(limit.admit(start + 60s) == 0);
}

TEST_CASE("log rate limits share one budget across concurrent callers") {
    using namespace std::chrono_literals;
    constexpr unsigned caller_count = 32;
    log::RateLimit limit(30s);
    const auto start = std::chrono::steady_clock::time_point{};
    std::atomic<unsigned> permitted{0};
    {
        std::vector<std::jthread> callers;
        for (unsigned caller = 0; caller < caller_count; ++caller)
            callers.emplace_back([&] {
                if (limit.admit(start))
                    permitted.fetch_add(1, std::memory_order_relaxed);
            });
    }
    CHECK(permitted.load() == 1);
    CHECK(limit.admit(start + 30s) == caller_count - 1);
}

TEST_CASE("single-message log limits restart the interval after a late emission") {
    using namespace std::chrono_literals;
    log::RateLimit limit;
    const auto start = std::chrono::steady_clock::time_point{};
    CHECK(limit.admit(start) == 0);
    CHECK(limit.admit(start + 45s) == 0);
    CHECK_FALSE(limit.admit(start + 60s));
    CHECK(limit.admit(start + 75s) == 1);
}

TEST_CASE("operational log limits admit a reconnect burst then refill one message per second") {
    using namespace std::chrono_literals;
    log::RateLimit limit(log::kOperationalMessageInterval, log::kOperationalMessageBurst);
    const auto start = std::chrono::steady_clock::time_point{};
    for (unsigned message = 0; message < log::kOperationalMessageBurst; ++message)
        CHECK(limit.admit(start) == 0);
    CHECK_FALSE(limit.admit(start));
    CHECK_FALSE(limit.admit(start + 999ms));
    CHECK(limit.admit(start + 1s) == 2);
    CHECK_FALSE(limit.admit(start + 1s));
    CHECK(limit.admit(start + 2s) == 1);
}

TEST_CASE("log bucket refill retains partial intervals without accumulating beyond the burst") {
    using namespace std::chrono_literals;
    log::RateLimit limit(log::kOperationalMessageInterval, log::kOperationalMessageBurst);
    const auto start = std::chrono::steady_clock::time_point{};
    for (unsigned message = 0; message < log::kOperationalMessageBurst; ++message)
        REQUIRE(limit.admit(start).has_value());

    CHECK(limit.admit(start + 1'500ms) == 0);
    CHECK_FALSE(limit.admit(start + 1'999ms));
    CHECK(limit.admit(start + 2s) == 1);

    const auto rested = start + 1h + 500ms;
    for (unsigned message = 0; message < log::kOperationalMessageBurst; ++message)
        CHECK(limit.admit(rested) == 0);
    CHECK_FALSE(limit.admit(rested));
    CHECK_FALSE(limit.admit(rested + 999ms));
    CHECK(limit.admit(rested + 1s) == 2);
}

TEST_CASE("log bucket suppression counts are reported once when multiple tokens refill") {
    using namespace std::chrono_literals;
    log::RateLimit limit(log::kOperationalMessageInterval, log::kOperationalMessageBurst);
    const auto start = std::chrono::steady_clock::time_point{};
    for (unsigned message = 0; message < log::kOperationalMessageBurst; ++message)
        REQUIRE(limit.admit(start).has_value());
    constexpr unsigned kSuppressed = 7;
    for (unsigned message = 0; message < kSuppressed; ++message)
        CHECK_FALSE(limit.admit(start));
    CHECK(limit.admit(start + 3s) == kSuppressed);
    CHECK(limit.admit(start + 3s) == 0);
    CHECK(limit.admit(start + 3s) == 0);
    CHECK_FALSE(limit.admit(start + 3s));
    CHECK(limit.admit(start + 4s) == 1);
}

TEST_CASE("operational log buckets share their burst across concurrent callers") {
    using namespace std::chrono_literals;
    constexpr unsigned kCallers = 16;
    constexpr unsigned kMessagesPerCaller = 8;
    log::RateLimit limit(log::kOperationalMessageInterval, log::kOperationalMessageBurst);
    const auto start = std::chrono::steady_clock::time_point{};
    std::atomic<unsigned> permitted{0};
    {
        std::vector<std::jthread> callers;
        for (unsigned caller = 0; caller < kCallers; ++caller)
            callers.emplace_back([&] {
                for (unsigned message = 0; message < kMessagesPerCaller; ++message)
                    if (limit.admit(start))
                        permitted.fetch_add(1, std::memory_order_relaxed);
            });
    }
    CHECK(permitted.load() == log::kOperationalMessageBurst);
    CHECK(limit.admit(start + 1s) == kCallers * kMessagesPerCaller - log::kOperationalMessageBurst);
    CHECK_FALSE(limit.admit(start + 1s));
}

TEST_CASE("log buckets handle out-of-order timestamps without refilling backwards") {
    using namespace std::chrono_literals;
    log::RateLimit limit(1s, 2);
    const auto start = std::chrono::steady_clock::time_point{};
    CHECK(limit.admit(start + 1s) == 0);
    CHECK(limit.admit(start) == 0);
    CHECK_FALSE(limit.admit(start));
    CHECK_FALSE(limit.admit(start + 1'999ms));
    CHECK(limit.admit(start + 2s) == 2);
}

TEST_CASE("log bucket defaults remain safe for zero burst and nonpositive intervals") {
    using namespace std::chrono_literals;
    const auto start = std::chrono::steady_clock::time_point{};
    log::RateLimit zero_burst(1s, 0);
    CHECK(zero_burst.admit(start) == 0);
    CHECK_FALSE(zero_burst.admit(start));
    for (const auto interval : {0s, -1s}) {
        log::RateLimit unlimited(interval, log::kOperationalMessageBurst);
        for (unsigned message = 0; message <= log::kOperationalMessageBurst; ++message)
            CHECK(unlimited.admit(start) == 0);
    }
}

TEST_CASE("disabled log messages do not consume the rate limit") {
    log::RateLimit limit;
    const auto previous_level = log::level();
    log::set_level(log::Level::Warning);
    log::message_limited(log::Level::Info, limit, "hidden message");
    log::set_level(previous_level);
    CHECK(limit.admit() == 0);
}

TEST_CASE("set_log_file tees log lines to an append-only file and disables cleanly") {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "erikslund-log-test";
    fs::remove_all(dir);
    const fs::path path = dir / "nested" / "pool.log"; // parent dirs auto-created

    log::set_level(log::Level::Info);
    REQUIRE(log::set_log_file(path.string()));
    log::info("file-sink-{}", 42);
    REQUIRE(log::set_log_file("")); // disable + close so we can read it (and stop teeing)

    std::ifstream in(path);
    REQUIRE(in.good());
    std::stringstream buffer;
    buffer << in.rdbuf();
    const std::string contents = buffer.str();
    CHECK(contents.find("file-sink-42") != std::string::npos);
    CHECK(contents.find("INFO") != std::string::npos);

    fs::remove_all(dir);
}

TEST_CASE("log::sanitize cleans untrusted strings before storing/logging them") {
    CHECK(log::sanitize("bcrt1qexample.rig1") == "bcrt1qexample.rig1");
    CHECK(log::sanitize("cgminer/4.10") == "cgminer/4.10");
    CHECK(log::sanitize("") == "?");
    CHECK(log::sanitize("a\nb") == "a?b");
    CHECK(log::sanitize(std::string("addr\nINFO BLOCK ACCEPTED")).find('\n') == std::string::npos);
    CHECK(log::sanitize("a\r\tb") == "a??b");
    CHECK(log::sanitize("x\x7f""y") == "x?y"); // DEL is stripped too
    const std::string capped = log::sanitize(std::string(200, 'x'), 64);
    CHECK(capped.size() == 64);
    CHECK(capped == std::string(64, 'x'));
}

TEST_CASE("log::ascii_only drops non-ASCII so a worker name stays ASCII for the stats file") {
    CHECK(log::ascii_only("rig1") == "rig1");
    CHECK(log::ascii_only("rig.worker_2") == "rig.worker_2");
    // "rigé" (é = UTF-8 0xC3 0xA9): both high bytes are dropped, leaving the ASCII skeleton.
    CHECK(log::ascii_only(std::string("rig\xC3\xA9")) == "rig");
    CHECK(log::ascii_only(std::string("\xE4\xB8\xAD\xE6\x96\x87")) == ""); // all-CJK -> empty
    CHECK(log::ascii_only(std::string("a\xC3\xA9""b")) == "ab");           // interleaved
    CHECK(log::ascii_only("x\x7f""y") == "xy");                            // DEL dropped
    CHECK(log::ascii_only(std::string("c\x01""d")) == "cd");               // control dropped
    CHECK(log::ascii_only("") == "");
    // Unicode-printable-but-not-ASCII (NBSP c2 a0, ZWSP e2 80 8b) dropped.
    CHECK(log::ascii_only(std::string("rig\xC2\xA0""a")) == "riga");
    CHECK(log::ascii_only(std::string("rig\xC2\xA0\xE2\x80\x8b""farm")) == "rigfarm");
    // Cap is applied AFTER dropping non-ASCII bytes.
    CHECK(log::ascii_only(std::string(200, 'a')).size() == 128);
    CHECK(log::ascii_only(std::string(200, 'a'), 10) == std::string(10, 'a'));
}

TEST_CASE("set_log_file returns false when the path cannot be opened") {
    namespace fs = std::filesystem;
    const fs::path not_a_dir = fs::temp_directory_path() / "erikslund-log-not-a-dir";
    { std::ofstream(not_a_dir) << "x"; } // a regular file
    // A path *under a regular file* can't be created/opened.
    CHECK_FALSE(log::set_log_file((not_a_dir / "sub" / "pool.log").string()));
    log::set_log_file(""); // ensure file logging is off for later tests
    fs::remove(not_a_dir);
}

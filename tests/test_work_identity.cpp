#include <doctest/doctest.h>

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <iterator>
#include <limits>
#include <set>
#include <string>
#include <vector>

#include <unistd.h>

#include "mining/work_identity.hpp"
#include "util/checked_counter.hpp"

using namespace erikslund;

namespace {

class WorkDirectory {
public:
    WorkDirectory() {
        std::string pattern = (std::filesystem::temp_directory_path() /
                                "ep-work-generation-XXXXXX").string();
        if (!::mkdtemp(pattern.data()))
            throw std::runtime_error("Cannot create work generation test directory");
        path = pattern;
    }
    ~WorkDirectory() {
        std::error_code ignored;
        // Permission tests must leave their owned temporary directory removable on failure.
        std::filesystem::permissions(path, std::filesystem::perms::owner_all, ignored);
        std::filesystem::remove_all(path, ignored);
    }
    std::filesystem::path path;
};

} // namespace

TEST_CASE("work generations survive restarts and create nested directories") {
    const WorkDirectory directory;
    const auto nested = directory.path / "data" / "stats";
    CHECK(mining::reserve_work_generation(nested) == 1);
    CHECK(mining::reserve_work_generation(nested) == 2);
    CHECK(mining::reserve_work_generation(nested) == 3);
    std::ifstream input(nested / "work-generation");
    std::string contents;
    std::getline(input, contents);
    CHECK(contents == "00000000000000000003");
    CHECK_FALSE(std::filesystem::exists(nested / "work-generation.tmp"));
}

TEST_CASE("concurrent startups reserve different durable work generations") {
    const WorkDirectory directory;
    const auto nested = directory.path / "data" / "stats";
    constexpr std::size_t kStartups = 16;
    std::vector<std::future<uint64_t>> startups;
    for (std::size_t index = 0; index < kStartups; ++index)
        startups.push_back(std::async(std::launch::async, [&] {
            return mining::reserve_work_generation(nested);
        }));
    std::set<uint64_t> generations;
    for (auto& startup : startups)
        generations.insert(startup.get());
    CHECK(generations.size() == kStartups);
    CHECK(*generations.begin() == 1);
    CHECK(*generations.rbegin() == kStartups);
    CHECK(mining::reserve_work_generation(nested) == kStartups + 1);
}

TEST_CASE("work generation paths preserve symlink traversal before a parent component") {
    const WorkDirectory directory;
    const auto target = directory.path / "actual" / "child";
    std::filesystem::create_directories(target);
    std::filesystem::create_directory_symlink(target, directory.path / "link");
    const auto configured = directory.path / "link" / ".." / "stats";
    const auto actual = directory.path / "actual" / "stats";

    CHECK(mining::reserve_work_generation(configured) == 1);
    CHECK(std::filesystem::exists(actual / "work-generation"));
    CHECK_FALSE(std::filesystem::exists(directory.path / "stats"));
    CHECK(mining::reserve_work_generation(actual) == 2);
    CHECK(mining::reserve_work_generation(configured) == 3);
}

TEST_CASE("work generations do not require read access to an unchanged ancestor") {
    const WorkDirectory directory;
    const auto writable = directory.path / "data";
    std::filesystem::create_directory(writable);
    auto stats_directory = writable / "stats";
    SUBCASE("the stats directory already exists") {
        std::filesystem::create_directory(stats_directory);
    }
    SUBCASE("nested stats directories must be created") {
        stats_directory = writable / "new" / "nested" / "stats";
    }
    std::filesystem::permissions(directory.path, std::filesystem::perms::owner_exec);
    // Root may bypass directory permissions; also run this file under an unprivileged UID.
    if (::geteuid() != 0) {
        std::error_code error;
        (void)std::filesystem::directory_iterator(directory.path, error);
        CHECK(error == std::errc::permission_denied);
    }
    CHECK(mining::reserve_work_generation(stats_directory) == 1);
    CHECK(mining::reserve_work_generation(stats_directory) == 2);
}

TEST_CASE("invalid or exhausted work generation state never resets") {
    const WorkDirectory directory;
    const auto path = directory.path / "work-generation";
    for (const std::string contents : {
             "", "1\n", "00000000000000000000\n", "0000000000000000000x\n",
             "18446744073709551616\n", "18446744073709551615\n",
             "00000000000000000001\nx", "00000000000000000001x"}) {
        { std::ofstream(path) << contents; }
        CHECK_THROWS(mining::reserve_work_generation(directory.path));
        std::ifstream input(path);
        CHECK(std::string(std::istreambuf_iterator<char>(input), {}) == contents);
    }
}

TEST_CASE("failed work generation writes preserve the last reservation") {
    const WorkDirectory directory;
    REQUIRE(mining::reserve_work_generation(directory.path) == 1);
    const auto temporary = directory.path / "work-generation.tmp";
    std::filesystem::create_directory(temporary);
    CHECK_THROWS(mining::reserve_work_generation(directory.path));
    std::filesystem::remove(temporary);
    CHECK(mining::reserve_work_generation(directory.path) == 2);
    { std::ofstream(temporary) << "interrupted unpublished write"; }
    CHECK(mining::reserve_work_generation(directory.path) == 3);
    CHECK_THROWS(mining::reserve_work_generation(directory.path / "work-generation"));
}

TEST_CASE("work generation state cannot be a symlink") {
    const WorkDirectory directory;
    const auto target = directory.path / "original";
    { std::ofstream(target) << "00000000000000000001\n"; }
    std::filesystem::create_symlink(target, directory.path / "work-generation");
    CHECK_THROWS(mining::reserve_work_generation(directory.path));
}

TEST_CASE("mining counters cannot wrap their encoded width") {
    for (std::size_t width = 1; width <= sizeof(uint64_t); ++width) {
        const auto maximum = util::counter_maximum(width);
        std::atomic<uint64_t> counter{maximum - 1};
        CHECK(util::next_counter(counter, maximum) == maximum);
        CHECK_THROWS_AS(util::next_counter(counter, maximum), std::overflow_error);
        CHECK_THROWS_AS(util::next_counter(counter, maximum), std::overflow_error);
        CHECK(counter.load() == maximum);
    }
    CHECK_THROWS_AS(util::counter_maximum(0), std::invalid_argument);
    CHECK_THROWS_AS(util::counter_maximum(9), std::invalid_argument);
}

TEST_CASE("concurrent allocation issues the final counter value only once") {
    std::atomic<uint64_t> counter{std::numeric_limits<uint64_t>::max() - 1};
    std::vector<std::future<bool>> allocations;
    for (std::size_t index = 0; index < 16; ++index)
        allocations.push_back(std::async(std::launch::async, [&] {
            try {
                (void)util::next_counter(counter);
                return true;
            } catch (const std::overflow_error&) {
                return false;
            }
        }));
    std::size_t successes = 0;
    for (auto& allocation : allocations)
        successes += allocation.get();
    CHECK(successes == 1);
    CHECK(counter.load() == std::numeric_limits<uint64_t>::max());
}

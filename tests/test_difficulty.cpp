#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

#include "util/difficulty.hpp"
#include "util/uint256.hpp"

using namespace erikslund;
using namespace erikslund::util;

namespace {

constexpr std::size_t kWireCorpusSampleCount = 50'000;
constexpr std::size_t kCompactCeilingSampleCount = 10'000;
constexpr std::size_t kTargetByteCount = 32;
constexpr std::size_t kWordByteCount = sizeof(uint64_t);
constexpr std::size_t kByteBits = std::numeric_limits<uint8_t>::digits;
constexpr uint64_t kSplitMixSeed = 0x6a09e667f3bcc909;
constexpr uint64_t kSplitMixIncrement = 0x9e3779b97f4a7c15;
constexpr uint64_t kSplitMixFirstMultiplier = 0xbf58476d1ce4e5b9;
constexpr uint64_t kSplitMixSecondMultiplier = 0x94d049bb133111eb;
constexpr uint64_t kFnvOffsetBasis = 0xcbf29ce484222325;
constexpr uint64_t kFnvPrime = 0x100000001b3;
constexpr uint64_t kWireCorpusFingerprint = 0xb6b622b67b9e9ca7;

uint64_t next_splitmix_word(uint64_t& state) {
    state += kSplitMixIncrement;
    uint64_t mixed = state;
    mixed = (mixed ^ (mixed >> 30)) * kSplitMixFirstMultiplier;
    mixed = (mixed ^ (mixed >> 27)) * kSplitMixSecondMultiplier;
    return mixed ^ (mixed >> 31);
}

void fingerprint_byte(uint64_t& fingerprint, uint8_t byte) {
    fingerprint = (fingerprint ^ byte) * kFnvPrime;
}

} // namespace

TEST_CASE("difficulty-1 compact target") {
    const auto target = target_from_compact(0x1d00ffff);
    CHECK(target.to_display_hex() ==
          "00000000ffff0000000000000000000000000000000000000000000000000000");
    CHECK(difficulty_from_compact(0x1d00ffff) == doctest::Approx(1.0));
}

TEST_CASE("known difficulty from historic nBits") {
    // 0x1b0404cb -> 16307.420938523983 (classic Bitcoin wiki example).
    CHECK(difficulty_from_compact(0x1b0404cb) == doctest::Approx(16307.420938523983));
}

TEST_CASE("target_from_difficulty inverts difficulty_from_target") {
    for (double d : {0.5, 1.0, 512.0, 1000.0, 1'000'000.0, 1e9}) {
        const auto target = target_from_difficulty(d);
        CHECK(difficulty_from_target(target) == doctest::Approx(d).epsilon(0.0001));
    }
}

TEST_CASE("meets_target") {
    const auto target = target_from_compact(0x1d00ffff);

    // The genesis block hash satisfies the genesis target.
    const auto genesis = uint256::from_display_hex(
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    CHECK(meets_target(genesis, target));

    // The maximum hash does not.
    const auto max_hash = uint256::from_display_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    CHECK_FALSE(meets_target(max_hash, target));

    // A target is trivially <= itself.
    CHECK(meets_target(target, target));
}

TEST_CASE("target_from_compact drops the sign bit (positive targets only)") {
    // Bit 0x00800000 of the mantissa is the sign bit and must be ignored, so
    // 0x1d80ffff yields the same target as 0x1d00ffff.
    CHECK(target_from_compact(0x1d80ffff).to_display_hex() ==
          target_from_compact(0x1d00ffff).to_display_hex());
}

TEST_CASE("target_from_compact small exponent (<= 3) right-shifts the mantissa") {
    // exponent 3: mantissa lands directly in the low three bytes.
    CHECK(target_from_compact(0x03123456).to_display_hex() ==
          "0000000000000000000000000000000000000000000000000000000000123456");
    // exponent 1: only the top mantissa byte survives the >> 16.
    CHECK(target_from_compact(0x01120000).to_display_hex() ==
          "0000000000000000000000000000000000000000000000000000000000000012");
    // exponent 2: top two mantissa bytes survive the >> 8.
    CHECK(target_from_compact(0x02123400).to_display_hex() ==
          "0000000000000000000000000000000000000000000000000000000000001234");
}

TEST_CASE("regtest-easy nBits 0x207fffff is a near-maximum target") {
    const auto target = target_from_compact(0x207fffff);
    // exponent 0x20 = 32, index 29: the mantissa fills the top bytes -> huge target.
    CHECK(target.to_display_hex() ==
          "7fffff0000000000000000000000000000000000000000000000000000000000");
    // Difficulty is well below 1 (target far above the diff-1 target).
    CHECK(difficulty_from_compact(0x207fffff) < 1.0);
}

TEST_CASE("difficulty_from_target of the zero target is positive infinity") {
    CHECK(difficulty_from_target(uint256{}) ==
          std::numeric_limits<double>::infinity());
}

TEST_CASE("target difficulty uses exact rational IEEE-754 rounding") {
    const auto target = uint256::from_display_hex(
        "b2317b89161291897871d7aa7854da6b"
        "3552120a91d8a9b2a5df94a848229100");
    const double difficulty = difficulty_from_target(target);

    // Exact rational conversion must produce this IEEE-754 bit pattern.
    CHECK(std::bit_cast<uint64_t>(difficulty) == 0x3df6fc65889cc8db);
    CHECK(target_from_difficulty(difficulty * 2.0).to_display_hex() ==
          "5918bdc48b094c000000000000000000"
          "00000000000000000000000000000000");
}

TEST_CASE("target conversion matches the pinned wire corpus") {
    uint64_t random_state = kSplitMixSeed;
    uint64_t fingerprint = kFnvOffsetBasis;

    for (std::size_t sample = 0; sample < kWireCorpusSampleCount; ++sample) {
        std::array<uint8_t, kTargetByteCount> target_bytes{};
        for (std::size_t word = 0;
             word < target_bytes.size() / kWordByteCount;
             ++word) {
            const uint64_t random_word = next_splitmix_word(random_state);
            for (std::size_t byte = 0; byte < kWordByteCount; ++byte)
                target_bytes[word * kWordByteCount + byte] =
                    static_cast<uint8_t>(random_word >> (byte * kByteBits));
        }
        if (std::ranges::all_of(target_bytes,
                                [](uint8_t byte) { return byte == 0; }))
            target_bytes.front() = 1;

        const double difficulty =
            difficulty_from_target(uint256::from_le_bytes(target_bytes));
        const uint64_t difficulty_bits = std::bit_cast<uint64_t>(difficulty);
        for (std::size_t byte = 0; byte < kWordByteCount; ++byte)
            fingerprint_byte(
                fingerprint,
                static_cast<uint8_t>(difficulty_bits >> (byte * kByteBits)));

        const auto doubled_target =
            target_from_difficulty(difficulty * 2.0).le_bytes();
        for (uint8_t byte : doubled_target)
            fingerprint_byte(fingerprint, byte);
    }

    CHECK(fingerprint == kWireCorpusFingerprint);
}

TEST_CASE("maximum share difficulty includes every hash meeting the network target") {
    for (const uint32_t bits : {0x01010000U, 0x03123456U, 0x1b0404cbU,
                               0x1d00ffffU, 0x207fffffU}) {
        CAPTURE(bits);
        const auto target = target_from_compact(bits);
        const double ceiling = maximum_difficulty_for_target(target);
        CHECK(std::isfinite(ceiling));
        CHECK(ceiling > 0.0);
        CHECK(ceiling <= difficulty_from_target(target));
        CHECK(target_from_difficulty(ceiling) >= target);
        CHECK(maximum_difficulty_for_target(target) == ceiling);
    }
    CHECK(maximum_difficulty_for_target(target_from_compact(0x1d00ffff)) == 1.0);
}

TEST_CASE("maximum share difficulty rounds below an upward-rounded network difficulty") {
    auto target_bytes = target_from_compact(0x1d00ffff).le_bytes();
    target_bytes.front() = 1;
    const auto target = uint256::from_le_bytes(target_bytes);

    REQUIRE(difficulty_from_target(target) == 1.0);
    const double ceiling = maximum_difficulty_for_target(target);
    CHECK(ceiling == std::nextafter(1.0, 0.0));
    CHECK(target_from_difficulty(ceiling) >= target);
}

TEST_CASE("maximum share difficulty avoids a target rounded below the network target") {
    const auto target = target_from_compact(0x1d3d64c4);
    REQUIRE(target_from_difficulty(difficulty_from_target(target)) < target);
    const double ceiling = maximum_difficulty_for_target(target);
    CHECK(ceiling < difficulty_from_target(target));
    CHECK(target_from_difficulty(ceiling) >= target);
}

TEST_CASE("maximum share difficulty corrects a round-trip error after downward rounding") {
    const auto target = uint256::from_display_hex(
        "00000000000000000000000000000000000117e9f8f42d36f24b9093554cd786");
    constexpr uint64_t kDownwardRoundedDifficultyBits = 0x46ed4404408705c9;
    constexpr uint64_t kSafeDifficultyBits = 0x46ed4404408705c8;
    const double downward_rounded = std::bit_cast<double>(kDownwardRoundedDifficultyBits);
    REQUIRE(target_from_difficulty(downward_rounded) < target);

    const double ceiling = maximum_difficulty_for_target(target);
    CHECK(std::bit_cast<uint64_t>(ceiling) == kSafeDifficultyBits);
    CHECK(target_from_difficulty(ceiling) >= target);
}

TEST_CASE("maximum share difficulty is safe across compact network targets") {
    constexpr uint32_t kMinimumExponent = 3;
    constexpr uint32_t kExponentCount = 30;
    constexpr uint32_t kMantissaMask = 0x007fffff;
    constexpr uint32_t kMinimumMantissa = 0x00010000;
    constexpr unsigned kCompactExponentShift = 24;
    uint64_t random_state = kSplitMixSeed;

    for (std::size_t sample = 0; sample < kCompactCeilingSampleCount; ++sample) {
        const uint32_t exponent = kMinimumExponent +
            static_cast<uint32_t>(next_splitmix_word(random_state) % kExponentCount);
        const uint32_t mantissa =
            static_cast<uint32_t>(next_splitmix_word(random_state)) & kMantissaMask;
        const uint32_t bits = (exponent << kCompactExponentShift) |
                              (mantissa | kMinimumMantissa);
        const auto target = target_from_compact(bits);
        const double ceiling = maximum_difficulty_for_target(target);
        CAPTURE(bits);
        CHECK(std::isfinite(ceiling));
        CHECK(ceiling > 0.0);
        CHECK(ceiling <= difficulty_from_target(target));
        CHECK(target_from_difficulty(ceiling) >= target);
    }
}

TEST_CASE("maximum share difficulty handles the full nonzero target range") {
    const auto maximum_target = uint256::from_display_hex(std::string(64, 'f'));
    const auto minimum_target = target_from_compact(0x01010000);
    for (const auto& target : {maximum_target, minimum_target}) {
        const double ceiling = maximum_difficulty_for_target(target);
        CHECK(std::isfinite(ceiling));
        CHECK(ceiling > 0.0);
        CHECK(target_from_difficulty(ceiling) >= target);
    }
    CHECK(maximum_difficulty_for_target(uint256{}) ==
          std::numeric_limits<double>::infinity());
}

TEST_CASE("target_from_difficulty(0) yields the all-ones (max) target") {
    CHECK(target_from_difficulty(0.0).to_display_hex() == std::string(64, 'f'));
}

TEST_CASE("difficulty doubles as the target halves") {
    // diff 2 corresponds to half the diff-1 target.
    const double d1 = difficulty_from_target(target_from_difficulty(1.0));
    const double d2 = difficulty_from_target(target_from_difficulty(2.0));
    CHECK(d2 == doctest::Approx(2.0 * d1).epsilon(0.0001));
}

TEST_CASE("format_difficulty renders plain decimal, never scientific") {
    CHECK(format_difficulty(1.0) == "1");
    CHECK(format_difficulty(20000.0) == "20000");
    CHECK(format_difficulty(1000000.0) == "1000000");
    // A non-integer >= 1 keeps up to two decimals, trailing zeros trimmed.
    CHECK(format_difficulty(1.5) == "1.5");
    CHECK(format_difficulty(1.25) == "1.25");
    CHECK(format_difficulty(2.0) == "2");
    // Sub-1 difficulty uses 4 significant digits (still decimal, not 2e+04).
    CHECK(format_difficulty(0.5) == "0.5");
    CHECK(format_difficulty(0.001) == "0.001");
    // No scientific notation ever appears.
    CHECK(format_difficulty(123456789.0).find('e') == std::string::npos);
    CHECK(format_difficulty(0.0001).find('e') == std::string::npos);
}

#include "util/difficulty.hpp"

#include <array>
#include <bit>
#include <cmath>
#include <limits>
#include <utility>

#include "util/endian.hpp"

namespace erikslund::util {

namespace {

constexpr double kDifficultyOneTarget =
    26959535291011309493156476344723991336010898738574164086137773096960.0;
constexpr double kTwoTo64 = 18446744073709551616.0;
constexpr double kTwoTo128 = 340282366920938463463374607431768211456.0;
constexpr double kTwoTo192 =
    6277101735386680763835789423207666416102355444464034512896.0;
constexpr double kMinimumRepresentableDifficulty = 2.4e-10;

constexpr std::size_t kWideWordCount = 5;
constexpr unsigned kWordBits = std::numeric_limits<uint64_t>::digits;
constexpr std::size_t kWordBytes = sizeof(uint64_t);
constexpr int kDoubleFractionBits = 52;
constexpr int kDoubleSignificandBits = kDoubleFractionBits + 1;
constexpr unsigned kDifficultyOneShift = 208;
using WideInteger = std::array<uint64_t, kWideWordCount>;

enum class RatioRounding { Nearest, Down };

WideInteger shift_left(const WideInteger& value, unsigned shift) {
    WideInteger shifted{};
    const std::size_t word_shift = shift / kWordBits;
    const unsigned bit_shift = shift % kWordBits;
    for (std::size_t source = 0; source < value.size(); ++source) {
        const std::size_t destination = source + word_shift;
        if (destination >= shifted.size())
            break;
        shifted[destination] |= value[source] << bit_shift;
        if (bit_shift != 0 && destination + 1 < shifted.size())
            shifted[destination + 1] |=
                value[source] >> (kWordBits - bit_shift);
    }
    return shifted;
}

int compare(const WideInteger& left, const WideInteger& right) {
    for (std::size_t index = left.size(); index-- > 0;) {
        if (left[index] < right[index])
            return -1;
        if (left[index] > right[index])
            return 1;
    }
    return 0;
}

int bit_length(const WideInteger& value) {
    for (std::size_t index = value.size(); index-- > 0;) {
        if (value[index] != 0)
            return static_cast<int>(index * kWordBits) +
                   std::bit_width(value[index]);
    }
    return 0;
}

void subtract(WideInteger& left, const WideInteger& right) {
    bool borrow = false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        const uint64_t subtrahend = right[index] + static_cast<uint64_t>(borrow);
        const bool addition_overflow = subtrahend < right[index];
        const bool next_borrow = addition_overflow || left[index] < subtrahend;
        left[index] -= subtrahend;
        borrow = next_borrow;
    }
}

std::pair<uint64_t, WideInteger> divide(const WideInteger& dividend,
                                        const WideInteger& divisor) {
    WideInteger remainder = dividend;
    uint64_t quotient = 0;
    const int highest_quotient_bit =
        bit_length(dividend) - bit_length(divisor);
    for (int quotient_bit = highest_quotient_bit; quotient_bit >= 0;
         --quotient_bit) {
        const WideInteger shifted_divisor =
            shift_left(divisor, static_cast<unsigned>(quotient_bit));
        if (compare(remainder, shifted_divisor) < 0)
            continue;
        subtract(remainder, shifted_divisor);
        quotient |= uint64_t{1} << quotient_bit;
    }
    return {quotient, remainder};
}

WideInteger difficulty_one_numerator() {
    WideInteger numerator{};
    numerator[kDifficultyOneShift / kWordBits] =
        uint64_t{0xffff} << (kDifficultyOneShift % kWordBits);
    return numerator;
}

WideInteger target_integer(const uint256& target) {
    WideInteger value{};
    const auto& bytes = target.le_bytes();
    for (std::size_t word = 0; word < bytes.size() / kWordBytes; ++word)
        value[word] = read_le64(bytes.data() + word * kWordBytes);
    return value;
}

double exact_ratio_to_double(const WideInteger& numerator,
                             const WideInteger& denominator,
                             RatioRounding rounding = RatioRounding::Nearest) {
    // Integer scaling avoids double-rounding the 256-bit denominator.
    int exponent = bit_length(numerator) - bit_length(denominator);
    const bool initial_exponent_is_reachable =
        exponent >= 0
            ? compare(numerator,
                      shift_left(denominator, static_cast<unsigned>(exponent))) >= 0
            : compare(shift_left(numerator, static_cast<unsigned>(-exponent)),
                      denominator) >= 0;
    if (!initial_exponent_is_reachable)
        --exponent;

    const int significand_shift = kDoubleFractionBits - exponent;
    const WideInteger dividend =
        significand_shift >= 0
            ? shift_left(numerator,
                         static_cast<unsigned>(significand_shift))
            : numerator;
    const WideInteger divisor =
        significand_shift < 0
            ? shift_left(denominator,
                         static_cast<unsigned>(-significand_shift))
            : denominator;
    auto [significand, remainder] = divide(dividend, divisor);

    const WideInteger twice_remainder = shift_left(remainder, 1);
    const int remainder_comparison = compare(twice_remainder, divisor);
    if (rounding == RatioRounding::Nearest &&
        (remainder_comparison > 0 ||
         (remainder_comparison == 0 && (significand & 1) != 0)))
        ++significand;

    constexpr uint64_t kSignificandOverflow =
        uint64_t{1} << kDoubleSignificandBits;
    if (significand == kSignificandOverflow) {
        significand >>= 1;
        ++exponent;
    }
    return std::ldexp(static_cast<double>(significand),
                      exponent - kDoubleFractionBits);
}

} // namespace

uint256 target_from_compact(uint32_t nbits) {
    const uint32_t exponent = nbits >> 24;
    uint32_t mantissa = nbits & 0x007fffff; // drop sign bit; targets are positive

    std::array<uint8_t, 32> target{};
    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        target[0] = uint8_t(mantissa);
        target[1] = uint8_t(mantissa >> 8);
        target[2] = uint8_t(mantissa >> 16);
    } else {
        const size_t index = exponent - 3; // low mantissa byte offset
        if (index <= 31)
            target[index] = uint8_t(mantissa);
        if (index + 1 <= 31)
            target[index + 1] = uint8_t(mantissa >> 8);
        if (index + 2 <= 31)
            target[index + 2] = uint8_t(mantissa >> 16);
    }
    return uint256::from_le_bytes(target);
}

double difficulty_from_target(const uint256& target) {
    if (target.is_zero())
        return std::numeric_limits<double>::infinity();
    return exact_ratio_to_double(difficulty_one_numerator(),
                                 target_integer(target));
}

double difficulty_from_compact(uint32_t nbits) {
    return difficulty_from_target(target_from_compact(nbits));
}

double maximum_difficulty_for_target(const uint256& target) {
    if (target.is_zero())
        return std::numeric_limits<double>::infinity();
    double difficulty = exact_ratio_to_double(difficulty_one_numerator(),
                                              target_integer(target), RatioRounding::Down);
    // Both difficulty and its round-trip target must stay on the easier side.
    while (target_from_difficulty(difficulty) < target)
        difficulty = std::nextafter(difficulty, 0.0);
    return difficulty;
}

uint256 target_from_difficulty(double difficulty) {
    std::array<uint8_t, 32> target{};
    // Clamp quotients above 256 bits before integer conversion becomes undefined.
    if (!(difficulty > kMinimumRepresentableDifficulty)) {
        target.fill(0xff);
        return uint256::from_le_bytes(target);
    }

    double remaining = kDifficultyOneTarget / difficulty;

    uint64_t target_word = uint64_t(remaining / kTwoTo192);
    write_le64(target.data() + 24, target_word);
    remaining -= double(target_word) * kTwoTo192;

    target_word = uint64_t(remaining / kTwoTo128);
    write_le64(target.data() + 16, target_word);
    remaining -= double(target_word) * kTwoTo128;

    target_word = uint64_t(remaining / kTwoTo64);
    write_le64(target.data() + 8, target_word);
    remaining -= double(target_word) * kTwoTo64;

    target_word = uint64_t(remaining);
    write_le64(target.data(), target_word);

    return uint256::from_le_bytes(target);
}

bool meets_target(const uint256& hash, const uint256& target) {
    return hash <= target;
}

} // namespace erikslund::util

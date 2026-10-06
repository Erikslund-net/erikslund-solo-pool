#include <doctest/doctest.h>

#include <format>
#include <string>
#include <vector>

#include "bitcoin/block_template.hpp"
#include "bitcoin/coinbase.hpp"
#include "gbt_fixture.hpp"
#include "stratum/job.hpp"
#include "util/difficulty.hpp"
#include "util/hex.hpp"
#include "util/merkle.hpp"
#include "util/uint256.hpp"

using namespace erikslund;
using namespace erikslund::stratum;
using namespace erikslund::util;
using namespace erikslund::test;

// Pinned values cover every byte that contributes to miner work.
namespace {

const std::string kPrevhash =
    "00000000000000000000abcdef0123456789abcdef0123456789abcdef012345";

gbt_json fixture_json(const std::string& bits) {
    gbt_json tx1 = gbt_json::object_t{};
    tx1["data"] = std::string("0123456789abcdef");
    tx1["txid"] = std::string(64, '1');
    gbt_json tx2 = gbt_json::object_t{};
    tx2["data"] = std::string("fedcba9876543210");
    tx2["txid"] = std::string(64, '2');

    gbt_json t = gbt_json::object_t{};
    t["height"] = 170;
    t["version"] = 0x20000000;
    t["curtime"] = 1700000000;
    t["bits"] = bits;
    t["coinbasevalue"] = 5000000000LL;
    t["previousblockhash"] = kPrevhash;
    t["default_witness_commitment"] = std::string("6a24aa21a9ed") + std::string(64, '0');
    t["transactions"] = gbt_json::array_t{};
    t["transactions"].get_array().push_back(std::move(tx1));
    t["transactions"].get_array().push_back(std::move(tx2));
    return t;
}

Job make_job(const std::string& bits = "1d00ffff") {
    const auto block_template = from_template(fixture_json(bits));
    const Bytes tag{'/', 'e', 'r', 'i', 'k', 's', 'l', 'u', 'n', 'd', '/'};
    return Job("job1", block_template, tag, 4, 4, 1);
}

ShareInput good_share(const Bytes& coinbase2, const Bytes& extranonce1, uint256 share_target) {
    ShareInput input;
    input.coinbase2 = coinbase2;
    input.extranonce1 = extranonce1;
    input.extranonce2_hex = "01020304";
    input.ntime_hex = "6553f100";
    input.nonce_hex = "2a2a2a2a";
    input.share_target = share_target;
    input.now_unix = 1700000000;
    return input;
}

// Parse the outputs of a coinbase2 built with an EMPTY tag:
//   nSequence(4) | varint count | [ value(8, LE) | varint scriptlen | script ] | nLockTime(4).
// counts and script lengths in these tests are < 0xfd, so each varint is one byte.
struct CoinbaseOut {
    uint64_t value;
    std::string script_hex;
};
inline std::vector<CoinbaseOut> parse_coinbase_outputs(const Bytes& cb2) {
    size_t i = 4; // skip nSequence; the tag is empty in the donation tests below
    const uint8_t count = cb2[i++];
    std::vector<CoinbaseOut> outs;
    for (uint8_t k = 0; k < count; ++k) {
        uint64_t value = 0;
        for (int b = 0; b < 8; ++b)
            value |= static_cast<uint64_t>(cb2[i + b]) << (8 * b);
        i += 8;
        const uint8_t len = cb2[i++];
        outs.push_back({value, to_hex(Bytes(cb2.begin() + i, cb2.begin() + i + len))});
        i += len;
    }
    return outs;
}

} // namespace

TEST_CASE("jobs cache a conservative network ceiling without changing display difficulty") {
    for (const std::string bits : {"1d00ffff", "1b0404cb", "207fffff"}) {
        CAPTURE(bits);
        const auto job = make_job(bits);
        const auto target = target_from_compact(job.bits());
        const double ceiling = maximum_difficulty_for_target(target);
        CHECK(job.network_target() == target);
        CHECK(job.network_difficulty() == difficulty_from_target(target));
        CHECK(job.maximum_share_difficulty() == ceiling);
        CHECK(target_from_difficulty(job.maximum_share_difficulty()) >= target);
        CHECK(job.maximum_share_difficulty() == ceiling);
    }
}

TEST_CASE("work_signature is stable for identical work and changes with ntime/txs") {
    const Bytes tag{'/', 'x', '/'};
    const auto base = fixture_json("1d00ffff");

    const Job a("a", from_template(base), tag, 4, 4, 1);
    const Job b("b", from_template(base), tag, 4, 4, 1);
    CHECK(a.work_signature() == b.work_signature()); // only the job_id differs -> same work

    auto later = base;
    later["curtime"] = base["curtime"].get<double>() + 30;
    const Job c("c", from_template(later), tag, 4, 4, 1);
    CHECK(a.work_signature() != c.work_signature()); // ntime advanced -> genuinely fresh work

    auto more = base;
    gbt_json tx3 = gbt_json::object_t{};
    tx3["data"] = std::string("aabbccdd");
    tx3["txid"] = std::string(64, '3');
    more["transactions"].get_array().push_back(std::move(tx3));
    const Job d("d", from_template(more), tag, 4, 4, 1);
    CHECK(a.work_signature() != d.work_signature()); // new transaction -> different merkle
}

TEST_CASE("Job reproduces the pinned golden vectors byte for byte") {
    const Job job = make_job();
    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const Bytes coinbase2 = job.build_coinbase2(payout);
    const Bytes extranonce1 = from_hex("abbaabba");
    const Bytes extranonce2 = from_hex("01020304");

    CHECK(job.coinbase1_hex() == "01000000010000000000000000000000000000000000000000000000000000"
                                 "000000000000ffffffff1602aa00");
    CHECK(to_hex(coinbase2) ==
          "2f6572696b736c756e642fffffffff0200f2052a01000000160014751e76e8199196d454941c45d1b3"
          "a323f1433bd60000000000000000266a24aa21a9ed00000000000000000000000000000000000000000"
          "0000000000000000000000000000000");
    CHECK(job.prevhash_stratum() ==
          "ef0123456789abcdef0123456789abcdef0123450000abcd0000000000000000");
    CHECK(job.version_hex() == "20000000");
    CHECK(job.nbits_hex() == "1d00ffff");
    CHECK(job.ntime_hex() == "6553f100");
    CHECK(job.merkle_branch_hex() ==
          std::vector<std::string>{
              "1111111111111111111111111111111111111111111111111111111111111111",
              "1e195ab43b27f0aec7055b81277c8f0ade35b1246a8d44c9aadb4ce7431f3108"});

    const uint256 max_target = uint256::from_display_hex(std::string(64, 'f'));
    const auto result = job.validate_share(good_share(coinbase2, extranonce1, max_target));
    REQUIRE(result);
    CHECK_FALSE(result->is_block); // 1d00ffff is hard; this nonce doesn't solve it
    CHECK(to_hex(result->header) ==
          "00000020452301efcdab8967452301efcdab8967452301efcdab0000000000000000000074185af0df"
          "59583eea8894ec1e7fbe700acf31e90df110c0f85c77687184423500f15365ffff001d2a2a2a2a");
    CHECK(result->block_hash_hex() ==
          "ba5564b906d836b684db96f29da3c63a87694ee4542d5f8350b08c4e09ea24f9");

    // legacy coinbase = coinbase1 || extranonce1 || extranonce2 || coinbase2 (each golden above).
    const std::string expected_legacy =
        job.coinbase1_hex() + to_hex(extranonce1) + "01020304" + to_hex(coinbase2);
    CHECK(to_hex(result->legacy_coinbase) == expected_legacy);

    Bytes standard_prefix = extranonce1;
    append(standard_prefix, extranonce2);
    const StandardWork standard_work =
        job.build_standard_work(payout, standard_prefix);
    CHECK(to_hex(standard_work.legacy_coinbase) == expected_legacy);

    StandardShareInput standard_input;
    standard_input.legacy_coinbase = standard_work.legacy_coinbase;
    standard_input.merkle_root = standard_work.merkle_root;
    standard_input.ntime = 1700000000;
    standard_input.nonce = 0x2a2a2a2a;
    standard_input.version = 0x20000000;
    standard_input.share_target = max_target;
    standard_input.now_unix = 1700000000;
    const auto standard_result = job.validate_standard_share(standard_input);
    REQUIRE(standard_result);
    CHECK(standard_result->header == result->header);
    CHECK(standard_result->legacy_coinbase == result->legacy_coinbase);

    const ExtendedWork extended_work = job.build_extended_work(payout);
    CHECK(extended_work.coinbase_tx_prefix == from_hex(job.coinbase1_hex()));
    CHECK(extended_work.coinbase_tx_suffix == coinbase2);
    REQUIRE(extended_work.merkle_path.size() == job.merkle_branch_hex().size());
    for (size_t i = 0; i < extended_work.merkle_path.size(); ++i)
        CHECK(to_hex(extended_work.merkle_path[i]) == job.merkle_branch_hex()[i]);

    Bytes extended_legacy = extended_work.coinbase_tx_prefix;
    append(extended_legacy, extranonce1);
    append(extended_legacy, extranonce2);
    append(extended_legacy, extended_work.coinbase_tx_suffix);
    CHECK(to_hex(extended_legacy) == expected_legacy);
    CHECK(merkle_root_from_branch(sha256d(extended_legacy), extended_work.merkle_path) ==
          standard_work.merkle_root);

    ExtendedShareInput extended_input;
    extended_input.extranonce_prefix = extranonce1;
    extended_input.extranonce = extranonce2;
    extended_input.extranonce_size = extranonce2.size();
    extended_input.ntime = 1700000000;
    extended_input.nonce = 0x2a2a2a2a;
    extended_input.version = 0x20000000;
    extended_input.share_target = max_target;
    extended_input.now_unix = 1700000000;
    const auto extended_result = job.validate_extended_share(extended_work, extended_input);
    REQUIRE(extended_result);
    CHECK(extended_result->header == result->header);
    CHECK(extended_result->legacy_coinbase == result->legacy_coinbase);

    // Full block = header || varint(txn_count+1) || segwit-coinbase || txn_data.
    // Segwit serialization inserts marker/flag after nVersion and the 32-byte
    // reserved-value witness (01 20 <32 zero>) before nLockTime.
    const std::string version = expected_legacy.substr(0, 8);
    const std::string locktime = expected_legacy.substr(expected_legacy.size() - 8);
    const std::string body = expected_legacy.substr(8, expected_legacy.size() - 16);
    const std::string segwit_coinbase =
        version + "0001" + body + "0120" + std::string(64, '0') + locktime;
    const std::string expected_block = to_hex(result->header) + "03" + segwit_coinbase +
                                       "0123456789abcdef" + "fedcba9876543210";
    CHECK(job.build_block_hex(result->legacy_coinbase, result->header) == expected_block);
    CHECK(job.build_block_hex(extended_result->legacy_coinbase, extended_result->header) ==
          expected_block);
}

TEST_CASE("SV2 Standard work requires the full template extranonce") {
    const Job job = make_job();
    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    CHECK_THROWS_AS(job.build_standard_work(payout, Bytes(7, 0)), std::invalid_argument);
    CHECK_NOTHROW(job.build_standard_work(payout, Bytes(8, 0)));
}

TEST_CASE("SV2 Extended shares require the negotiated extranonce partition") {
    const Job job = make_job();
    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const ExtendedWork work = job.build_extended_work(payout);
    const Bytes prefix = from_hex("abbaabba");
    const Bytes extranonce = from_hex("01020304");
    const uint256 max_target = uint256::from_display_hex(std::string(64, 'f'));

    ExtendedShareInput input;
    input.extranonce_prefix = prefix;
    input.extranonce = extranonce;
    input.extranonce_size = extranonce.size();
    input.ntime = 1700000000;
    input.version = 0x20000000;
    input.share_target = max_target;
    input.now_unix = 1700000000;
    REQUIRE(job.validate_extended_share(work, input));

    SUBCASE("submitted extranonce is shorter than negotiated") {
        const Bytes short_extranonce(extranonce.size() - 1, 0);
        input.extranonce = short_extranonce;
        CHECK(job.validate_extended_share(work, input).error().reason ==
              ShareReject::InvalidExtranonce2Size);
    }
    SUBCASE("submitted extranonce is longer than negotiated") {
        const Bytes long_extranonce(extranonce.size() + 1, 0);
        input.extranonce = long_extranonce;
        CHECK(job.validate_extended_share(work, input).error().reason ==
              ShareReject::InvalidExtranonce2Size);
    }
    SUBCASE("negotiated partition must fill the template extranonce") {
        input.extranonce_size -= 1;
        CHECK(job.validate_extended_share(work, input).error().reason ==
              ShareReject::InvalidExtranonce2Size);
    }
    SUBCASE("prefix cannot exceed the template extranonce") {
        const Bytes oversized_prefix(9, 0);
        input.extranonce_prefix = oversized_prefix;
        CHECK(job.validate_extended_share(work, input).error().reason ==
              ShareReject::InvalidExtranonce2Size);
    }
}

TEST_CASE("a solved share is detected as a block on an easy target") {
    const Job job = make_job("207fffff"); // regtest-easy network target
    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const Bytes coinbase2 = job.build_coinbase2(payout);
    const Bytes extranonce1 = from_hex("abbaabba");
    const uint256 max_target = uint256::from_display_hex(std::string(64, 'f'));

    // ~half of all nonces solve the regtest-easy target; scan a fixed range so
    // the test is deterministic, then confirm the block assembles header-first.
    bool found_block = false;
    for (uint32_t nonce = 0; nonce < 64 && !found_block; ++nonce) {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        const std::string nonce_hex = std::format("{:08x}", nonce);
        input.nonce_hex = nonce_hex;
        const auto result = job.validate_share(input);
        REQUIRE(result);
        if (result->is_block) {
            found_block = true;
            CHECK(job.build_block_hex(result->legacy_coinbase, result->header)
                      .rfind(to_hex(result->header), 0) == 0);
        }
    }
    CHECK(found_block);
}

TEST_CASE("share rejection paths") {
    const Job job = make_job();
    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const Bytes coinbase2 = job.build_coinbase2(payout);
    const Bytes extranonce1 = from_hex("abbaabba");
    const uint256 max_target = uint256::from_display_hex(std::string(64, 'f'));

    SUBCASE("malformed extranonce2") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.extranonce2_hex = "zzzz";
        CHECK(job.validate_share(input).error().reason == ShareReject::MalformedField);
    }
    SUBCASE("wrong extranonce2 size") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.extranonce2_hex = "0102"; // 2 bytes, expected 4
        CHECK(job.validate_share(input).error().reason == ShareReject::InvalidExtranonce2Size);
    }
    SUBCASE("oversized extranonce2 is rejected before decode") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.extranonce2_hex = "010203040506"; // 6 bytes, expected 4
        CHECK(job.validate_share(input).error().reason == ShareReject::InvalidExtranonce2Size);
    }
    SUBCASE("ntime out of range") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.ntime_hex = "ffffffff"; // far in the future relative to now_unix
        CHECK(job.validate_share(input).error().reason == ShareReject::NtimeOutOfRange);
    }
    SUBCASE("below share target") {
        // share target = difficulty 1; the share's hash is far above it.
        ShareInput input = good_share(coinbase2, extranonce1, target_from_compact(0x1d00ffff));
        const auto result = job.validate_share(input);
        CHECK_FALSE(result);
        CHECK(result.error().reason == ShareReject::AboveTarget);
    }
}

TEST_CASE("Job exposes its template accessors") {
    const Job job = make_job("1d00ffff");
    CHECK(job.job_id() == "job1");
    CHECK(job.height() == 170);
    CHECK(job.txn_count() == 2);     // the fixture has two transactions
    CHECK(job.clean());              // default clean = true
    CHECK(job.version_hex() == "20000000");
    CHECK(job.nbits_hex() == "1d00ffff");
    // network_difficulty derives from nBits: 0x1d00ffff is difficulty 1.
    CHECK(job.network_difficulty() == doctest::Approx(1.0));
}

TEST_CASE("the regtest-easy job reports a sub-1 network difficulty") {
    const Job job = make_job("207fffff");
    CHECK(job.network_difficulty() < 1.0);
}

TEST_CASE("more share rejection and acceptance paths") {
    const Job job = make_job();
    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const Bytes coinbase2 = job.build_coinbase2(payout);
    const Bytes extranonce1 = from_hex("abbaabba");
    const uint256 max_target = uint256::from_display_hex(std::string(64, 'f'));

    SUBCASE("malformed ntime hex") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.ntime_hex = "zzzz";
        CHECK(job.validate_share(input).error().reason == ShareReject::MalformedField);
    }
    SUBCASE("malformed nonce hex") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.nonce_hex = "xyz0";
        CHECK(job.validate_share(input).error().reason == ShareReject::MalformedField);
    }
    SUBCASE("ntime far in the past is out of range") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.ntime_hex = "00000001"; // well below the job's curtime floor
        CHECK(job.validate_share(input).error().reason == ShareReject::NtimeOutOfRange);
    }
    SUBCASE("ntime one second below curtime is rejected") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.ntime_hex = "6553f0ff"; // fixture curtime 0x6553f100 - 1
        CHECK(job.validate_share(input).error().reason == ShareReject::NtimeOutOfRange);
    }
    SUBCASE("ntime exactly at curtime is accepted") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.ntime_hex = "6553f100"; // == fixture curtime 1700000000
        CHECK(job.validate_share(input).has_value());
    }
    // Submit-margin ceiling = now_unix + 7200 - kNtimeSubmitMargin(120) = 1700007080
    // (good_share() pins now_unix = 1700000000); these three bracket the exact boundary.
    SUBCASE("ntime at the submit-margin ceiling (now + 7200 - 120) is accepted") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.ntime_hex = "65540ca8"; // now_unix + 7080
        CHECK(job.validate_share(input).has_value());
    }
    SUBCASE("ntime one second above the submit margin is rejected") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.ntime_hex = "65540ca9"; // now_unix + 7081
        CHECK(job.validate_share(input).error().reason == ShareReject::NtimeOutOfRange);
    }
    SUBCASE("ntime at the old now+7200 ceiling now falls inside the forbidden margin") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.ntime_hex = "65540d20"; // now_unix + 7200 (forbidden by the 120s margin)
        CHECK(job.validate_share(input).error().reason == ShareReject::NtimeOutOfRange);
    }
}

TEST_CASE("version-rolling masks the header version") {
    const Job job = make_job();
    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const Bytes coinbase2 = job.build_coinbase2(payout);
    const Bytes extranonce1 = from_hex("abbaabba");
    const uint256 max_target = uint256::from_display_hex(std::string(64, 'f'));

    SUBCASE("bits inside the negotiated mask are applied") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.version_mask = 0x1fffe000u;
        input.version_bits_hex = "00002000"; // a bit within the mask
        const auto result = job.validate_share(input);
        REQUIRE(result);
        // header version word (little-endian, first 4 bytes) = base 0x20000000 | 0x00002000.
        CHECK(to_hex(result->header).substr(0, 8) == "00200020");
    }
    SUBCASE("bits outside the mask are rejected") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.version_mask = 0x1fffe000u;
        input.version_bits_hex = "00000001"; // not covered by the mask
        CHECK(job.validate_share(input).error().reason == ShareReject::VersionBitsOutsideMask);
    }
    SUBCASE("malformed version bits hex is rejected") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.version_mask = 0x1fffe000u;
        input.version_bits_hex = "zz";
        CHECK(job.validate_share(input).error().reason == ShareReject::MalformedVersionBits);
    }
    SUBCASE("non-zero bits without a negotiated mask are rejected (not silently dropped)") {
        // Rolling version without negotiating means the miner hashed a header the pool would
        // rebuild with the base version -> a real block would be silently lost. Reject visibly.
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.version_mask = 0;
        input.version_bits_hex = "ffffffff";
        CHECK(job.validate_share(input).error().reason == ShareReject::VersionRollingNotNegotiated);
    }
    SUBCASE("zero bits without a negotiated mask are a harmless no-op") {
        ShareInput input = good_share(coinbase2, extranonce1, max_target);
        input.version_mask = 0;
        input.version_bits_hex = "00000000"; // rolls nothing -> header unchanged, still valid
        const auto result = job.validate_share(input);
        REQUIRE(result);
        CHECK(to_hex(result->header).substr(0, 8) == "00000020"); // base version unchanged
    }
}

TEST_CASE("a rejected (above-target) share reports its difficulty in the error half") {
    const Job job = make_job(); // hard 1d00ffff target
    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const Bytes coinbase2 = job.build_coinbase2(payout);
    const Bytes extranonce1 = from_hex("abbaabba");

    ShareInput input = good_share(coinbase2, extranonce1, target_from_compact(0x1d00ffff));
    const auto result = job.validate_share(input);
    REQUIRE_FALSE(result);
    CHECK(result.error().reason == ShareReject::AboveTarget);
    CHECK(result.error().difficulty > 0.0);
}

TEST_CASE("reject_reason maps every code to a stable human string") {
    CHECK(reject_reason(ShareReject::None) == "ok");
    CHECK(reject_reason(ShareReject::InvalidExtranonce2Size) == "invalid extranonce2 size");
    CHECK(reject_reason(ShareReject::MalformedField) == "malformed share field");
    CHECK(reject_reason(ShareReject::NtimeOutOfRange) == "ntime out of range");
    CHECK(reject_reason(ShareReject::MalformedVersionBits) == "malformed version bits");
    CHECK(reject_reason(ShareReject::VersionRollingNotNegotiated) == "version rolling not negotiated");
    CHECK(reject_reason(ShareReject::VersionBitsOutsideMask) == "version bits outside negotiated mask");
    CHECK(reject_reason(ShareReject::AboveTarget) == "above target");
}

TEST_CASE("donation adds a second coinbase output and reduces the payout") {
    const auto block_template = from_template(fixture_json("1d00ffff"));
    const Bytes tag{'/', 'e', 'p', '/'};
    const Bytes donation = from_hex("0014" + std::string(40, 'a'));
    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");

    Job with_donation("d1", block_template, tag, 4, 4, 1, true, donation, 10.0);
    Job without_donation("n1", block_template, tag, 4, 4, 1, true);

    const std::string donated = to_hex(with_donation.build_coinbase2(payout));
    const std::string plain = to_hex(without_donation.build_coinbase2(payout));

    CHECK(donated != plain);
    CHECK(donated.find(to_hex(donation)) != std::string::npos); // donation script present
    // 10% of the fixture's 5,000,000,000 coinbasevalue = 500,000,000, little-endian.
    CHECK(donated.find("0065cd1d00000000") != std::string::npos);
}

TEST_CASE("Job honors Mining IPC coinbase fields and required outputs") {
    auto json = fixture_json("1d00ffff");
    json.get_object().erase("default_witness_commitment");
    auto block_template = from_template(json);
    block_template.coinbase_script_sig_prefix = from_hex("02aa00abcd");
    block_template.coinbase_version = 2;
    block_template.coinbase_sequence = 0x11223344;
    block_template.coinbase_lock_time = 0x55667788;
    block_template.coinbase_witness = Bytes(32, 0x42);
    const Bytes required_script = from_hex("51");
    block_template.coinbase_required_outputs = {{7, required_script}};

    // The template's version overrides the configured fallback version.
    const Job job("ipc", std::move(block_template), Bytes{}, 4, 4, 9);
    CHECK(job.coinbase1_hex().starts_with("02000000"));
    CHECK(job.coinbase1_hex().ends_with("0d02aa00abcd"));

    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const Bytes coinbase2 = job.build_coinbase2(payout);
    CHECK(to_hex(coinbase2).starts_with("44332211"));
    CHECK(to_hex(coinbase2).ends_with("88776655"));

    const auto outputs = parse_coinbase_outputs(coinbase2);
    REQUIRE(outputs.size() == 2);
    CHECK(outputs[0].value == 5000000000ULL);
    CHECK(outputs[0].script_hex == to_hex(payout));
    CHECK(outputs[1].value == 7);
    CHECK(outputs[1].script_hex == to_hex(required_script));

    Bytes legacy_coinbase = from_hex(job.coinbase1_hex());
    append(legacy_coinbase, Bytes(8, 0)); // extranonce1 + extranonce2
    append(legacy_coinbase, coinbase2);
    const std::string block_hex =
        job.build_block_hex(legacy_coinbase, Bytes(util::kHeaderSize, 0));
    CHECK(block_hex.find("0120" + to_hex(Bytes(32, 0x42))) != std::string::npos);
}

TEST_CASE("donation conserves the full reward across the two outputs") {
    const auto bt = from_template(fixture_json("1d00ffff"));
    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const Bytes donation = from_hex("0014" + std::string(40, 'b'));
    const Job job("c1", bt, /*tag=*/Bytes{}, 4, 4, 1, true, donation, 2.0);
    const auto outs = parse_coinbase_outputs(job.build_coinbase2(payout));
    REQUIRE(outs.size() >= 2);
    constexpr uint64_t kValue = 5000000000ULL;
    constexpr uint64_t kDonation = 100000000ULL; // 2% of 5e9
    CHECK(outs[0].value == kValue - kDonation);    // miner gets the remainder
    CHECK(outs[0].script_hex == to_hex(payout));
    CHECK(outs[1].value == kDonation);             // donation: exact amount
    CHECK(outs[1].script_hex == to_hex(donation)); // ...to the donation script
    uint64_t total = 0;
    for (const auto& o : outs)
        total += o.value;
    CHECK(total == kValue); // no satoshi created or lost (the 0-value commitment doesn't change it)
}

TEST_CASE("donation floors to whole satoshis, remainder to the miner") {
    auto j = fixture_json("1d00ffff");
    j["coinbasevalue"] = 1234567891LL; // an odd reward that does not divide evenly
    const auto bt = from_template(j);
    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const Bytes donation = from_hex("0014" + std::string(40, 'c'));
    const Job job("c2", bt, Bytes{}, 4, 4, 1, true, donation, 7.0);
    const auto outs = parse_coinbase_outputs(job.build_coinbase2(payout));
    REQUIRE(outs.size() >= 2);
    CHECK(outs[1].value == 86419752ULL);                 // floor(1234567891 * 7 / 100)
    CHECK(outs[0].value == 1234567891ULL - 86419752ULL); // miner keeps the rounding remainder
    uint64_t total = 0;
    for (const auto& o : outs)
        total += o.value;
    CHECK(total == 1234567891ULL);
}

TEST_CASE("a donation percent with no resolved script produces no donation output") {
    const auto bt = from_template(fixture_json("1d00ffff"));
    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const Job job("c3", bt, Bytes{}, 4, 4, 1, true, /*donation_script=*/Bytes{}, 10.0);
    const auto outs = parse_coinbase_outputs(job.build_coinbase2(payout));
    CHECK(outs[0].value == 5000000000ULL); // miner keeps the entire reward
    CHECK(outs[0].script_hex == to_hex(payout));
}

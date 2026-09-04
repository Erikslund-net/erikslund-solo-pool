#include <doctest/doctest.h>

#include <string>

#include "bitcoin/block_template.hpp"
#include "gbt_fixture.hpp"
#include "pool/pool.hpp"
#include "stratum/job.hpp"
#include "util/hex.hpp"
#include "util/sha256.hpp"
#include "util/uint256.hpp"

using namespace erikslund;
using namespace erikslund::stratum;
using namespace erikslund::util;
using namespace erikslund::test;

// fastblock work is an empty (coinbase-only) template; commitment = sha256d(64 zeros).
TEST_CASE("empty-block (fastblock) job builds a single-transaction block") {
    gbt_json t = gbt_json::object_t{};
    t["height"] = 200;
    t["version"] = 0x20000000;
    t["curtime"] = 1700000000;
    t["bits"] = std::string("1d00ffff");
    t["coinbasevalue"] = 5000000000LL;
    t["previousblockhash"] = std::string(64, '0');
    t["default_witness_commitment"] = "6a24aa21a9ed" + to_hex(sha256d(Bytes(64, 0)));
    t["transactions"] = gbt_json::array_t{};

    const auto block_template = from_template(t);
    Job job("e1", block_template, Bytes{'/', 'e', '/'}, 4, 4, 1, true);
    CHECK(job.txn_count() == 0);
    CHECK(job.merkle_branch_hex().empty()); // no other txns -> empty merkle branch

    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const Bytes coinbase2 = job.build_coinbase2(payout);
    const Bytes extranonce1 = from_hex("e06ae06a");

    ShareInput input;
    input.coinbase2 = coinbase2;
    input.extranonce1 = extranonce1;
    input.extranonce2_hex = "01020304";
    input.ntime_hex = "6553f100";
    input.nonce_hex = "00000000";
    input.share_target = uint256::from_display_hex(std::string(64, 'f'));
    input.now_unix = 1700000000;
    const auto result = job.validate_share(input);
    REQUIRE(result);

    // block = header || varint(1) || coinbase  (only the coinbase, no other txns)
    const std::string block = job.build_block_hex(result->legacy_coinbase, result->header);
    CHECK(block.rfind(to_hex(result->header) + "01", 0) == 0);
}

TEST_CASE("a template without a witness commitment assembles a legacy (non-segwit) block") {
    gbt_json t = gbt_json::object_t{};
    t["height"] = 200;
    t["version"] = 0x20000000;
    t["curtime"] = 1700000000;
    t["bits"] = std::string("1d00ffff");
    t["coinbasevalue"] = 5000000000LL;
    t["previousblockhash"] = std::string(64, '0');
    // No default_witness_commitment field.
    t["transactions"] = gbt_json::array_t{};

    const auto block_template = from_template(t);
    Job job("legacy1", block_template, Bytes{'/', 'e', '/'}, 4, 4, 1);

    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const Bytes coinbase2 = job.build_coinbase2(payout);
    const Bytes extranonce1 = from_hex("e06ae06a");

    ShareInput input;
    input.coinbase2 = coinbase2;
    input.extranonce1 = extranonce1;
    input.extranonce2_hex = "01020304";
    input.ntime_hex = "6553f100";
    input.nonce_hex = "00000000";
    input.share_target = uint256::from_display_hex(std::string(64, 'f'));
    input.now_unix = 1700000000;
    const auto result = job.validate_share(input);
    REQUIRE(result);

    // Without segwit, the block body is header || varint(1) || the legacy coinbase verbatim
    // (no 00 01 marker/flag, no witness) -> the legacy coinbase appears right after the count.
    const std::string block = job.build_block_hex(result->legacy_coinbase, result->header);
    CHECK(block == to_hex(result->header) + "01" + to_hex(result->legacy_coinbase));
    // The segwit marker/flag must NOT be present immediately after the count.
    CHECK(block.find(to_hex(result->header) + "01" + "0001") == std::string::npos);
}

// The on_zmq_block gate deciding whether one-block-ahead empty work is sound to broadcast (vs
// falling through to the GBT). next_height + confirmations come from getblockheader on the
// notified hash, so the height is exact even across a reorg or a multi-block tip advance.
TEST_CASE("fastblock_eligible gates one-block-ahead empty work") {
    const std::string held = "11";   // the tip the cached template mines on top of
    const std::string fresh = "22";  // a genuinely new tip from ZMQ
    const std::string kBits = "1d00ffff"; // the new tip's nBits, reused by the empty job

    CHECK(fastblock_eligible(true, fresh, held, 101, 1, "main", kBits));
    CHECK(fastblock_eligible(true, fresh, held, 101, 1, "regtest", kBits));
    CHECK(fastblock_eligible(true, fresh, held, 101, 1, "signet", kBits));

    SUBCASE("no nBits for the new tip -> skip") {
        CHECK_FALSE(fastblock_eligible(true, fresh, held, 101, 1, "main", ""));
    }
    SUBCASE("no template yet -> skip") {
        CHECK_FALSE(fastblock_eligible(false, fresh, held, 101, 1, "main", kBits));
    }
    SUBCASE("notification matches the held tip -> skip (the GBT already advanced)") {
        CHECK_FALSE(fastblock_eligible(true, held, held, 101, 1, "main", kBits));
    }
    SUBCASE("stale or superseded notification -> skip (not the active tip)") {
        // A delayed ZMQ notification: the hash already has a child (confirmations >= 2).
        // Building on it would put every miner on a superseded parent.
        CHECK_FALSE(fastblock_eligible(true, fresh, held, 101, 2, "main", kBits));
        // Reorged away entirely (-1) or unknown (0): never build on it.
        CHECK_FALSE(fastblock_eligible(true, fresh, held, 101, -1, "main", kBits));
        CHECK_FALSE(fastblock_eligible(true, fresh, held, 101, 0, "main", kBits));
    }
    SUBCASE("next block at a difficulty-retarget boundary -> skip (new bits unknown)") {
        CHECK_FALSE(fastblock_eligible(true, fresh, held, 2016, 1, "main", kBits));
        CHECK(fastblock_eligible(true, fresh, held, 2015, 1, "main", kBits));
        CHECK(fastblock_eligible(true, fresh, held, 2017, 1, "main", kBits));
    }
    SUBCASE("testnet's 20-minute rule makes nBits timestamp-dependent at EVERY height -> skip") {
        CHECK_FALSE(fastblock_eligible(true, fresh, held, 101, 1, "test", kBits));
        CHECK_FALSE(fastblock_eligible(true, fresh, held, 101, 1, "testnet4", kBits));
    }
}

TEST_CASE("block_subsidy mirrors consensus GetBlockSubsidy") {
    // Mainnet interval 210000.
    CHECK(block_subsidy(0, 210000) == 5000000000ULL);        // 50 BTC
    CHECK(block_subsidy(209999, 210000) == 5000000000ULL);   // last pre-halving block
    CHECK(block_subsidy(210000, 210000) == 2500000000ULL);   // first halving
    CHECK(block_subsidy(420000, 210000) == 1250000000ULL);   // second halving
    CHECK(block_subsidy(840000, 210000) == 312500000ULL);    // fourth halving (3.125 BTC, 2024)
    // 5e9 < 2^33, so 33+ halvings shift to zero; >= 64 halvings is the consensus hard stop.
    CHECK(block_subsidy(33L * 210000, 210000) == 0);
    CHECK(block_subsidy(64L * 210000, 210000) == 0);
    CHECK(block_subsidy(100L * 210000, 210000) == 0);
    // Regtest halves every 150.
    CHECK(block_subsidy(149, 150) == 5000000000ULL);
    CHECK(block_subsidy(150, 150) == 2500000000ULL);
}

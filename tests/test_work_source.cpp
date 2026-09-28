// WorkSource boundary tests: the RpcWorkSource adapter maps RpcClient replies onto the ChainInfo /
// HeaderFacts / tip primitives with the exact field defaults the pool depended on inline (notably
// confirmations == -1 when absent, which gates fastblock).
#include <doctest/doctest.h>

#include <map>
#include <stdexcept>
#include <string>

#include <glaze/glaze.hpp>

#include "bitcoin/rpc_client.hpp"
#include "bitcoin/work_source_rpc.hpp"
#include "core/errors.hpp"

using namespace erikslund;
using json = glz::generic;

namespace {

// Dispatches call() by the method named in the JSON-RPC payload, returning a canned result generic
// (call_one returns the already-unwrapped result, matching RpcClient::call()).
class CannedRpc : public bitcoin::RpcClient {
public:
    CannedRpc() : RpcClient("http://fake", "u", "p", /*timeout_seconds=*/1) {}
    json header;    // getblockheader result
    json chaininfo; // getblockchaininfo result
    std::string tip = "0000tip";

protected:
    json call_one(const Resolved&, const std::string& payload, long) override {
        if (payload.find("getblockheader") != std::string::npos)
            return header;
        if (payload.find("getblockchaininfo") != std::string::npos)
            return chaininfo;
        if (payload.find("getbestblockhash") != std::string::npos)
            return json(tip);
        throw RpcError("CannedRpc: unexpected method in " + payload);
    }
};

// A node's view of several blocks: getblockheader answers per hash (-5 for unknown ones) and
// getchaintips returns the configured tips.
class ChainRpc : public bitcoin::RpcClient {
public:
    ChainRpc() : RpcClient("http://fake", "u", "p", /*timeout_seconds=*/1) {}
    std::map<std::string, json> headers;
    json tips = json::array_t{};
    int chaintips_calls = 0;

    void add_header(const std::string& hash, double height, double confirmations,
                    const std::string& previous = {}) {
        json header = json::object_t{};
        header["hash"] = hash;
        header["height"] = height;
        header["confirmations"] = confirmations;
        if (!previous.empty())
            header["previousblockhash"] = previous;
        headers[hash] = std::move(header);
    }

    void add_tip(const std::string& hash, double height, double branch_length,
                 const std::string& status) {
        json tip = json::object_t{};
        tip["hash"] = hash;
        tip["height"] = height;
        tip["branchlen"] = branch_length;
        tip["status"] = status;
        tips.get_array().push_back(std::move(tip));
    }

protected:
    json call_one(const Resolved&, const std::string& payload, long) override {
        if (payload.find("getchaintips") != std::string::npos) {
            ++chaintips_calls;
            return tips;
        }
        if (payload.find("getblockheader") != std::string::npos) {
            for (const auto& [hash, header] : headers)
                if (payload.find(hash) != std::string::npos)
                    return header;
            throw RpcError("Block not found", -5);
        }
        throw RpcError("ChainRpc: unexpected method in " + payload);
    }
};

const std::string kActiveTip(64, '1');
const std::string kCurrentParent(64, '2');
const std::string kDescendant(64, '3');

} // namespace

TEST_CASE("RpcWorkSource maps chain info and the tip probe") {
    CannedRpc rpc;
    rpc.chaininfo = json::object_t{};
    rpc.chaininfo["chain"] = std::string("main");
    rpc.chaininfo["blocks"] = 850000.0;
    bitcoin::RpcWorkSource source(rpc);

    const auto info = source.detect_chain();
    CHECK(info.chain == "main");
    CHECK(info.blocks == 850000);
    CHECK(source.get_tip() == "0000tip");
}

TEST_CASE("RpcWorkSource::fetch_header extracts every field the fastblock gate needs") {
    CannedRpc rpc;
    rpc.header = json::object_t{};
    rpc.header["height"] = 849999.0;
    rpc.header["confirmations"] = 1.0;
    rpc.header["bits"] = std::string("170355f0");
    rpc.header["mediantime"] = 1700000000.0;
    bitcoin::RpcWorkSource source(rpc);

    const auto facts = source.fetch_header("somehash");
    CHECK(facts.height == 849999);
    CHECK(facts.confirmations == 1);
    CHECK(facts.bits_hex == "170355f0");
    CHECK(facts.mediantime == 1700000000u);
}

TEST_CASE("RpcWorkSource::fetch_header defaults confirmations to -1 when absent") {
    // The fastblock gate treats confirmations != 1 as "not the active tip". A missing field MUST
    // read -1 (not 0), matching the old inline json_int(header,"confirmations",-1).
    CannedRpc rpc;
    rpc.header = json::object_t{};
    rpc.header["height"] = 849999.0;
    rpc.header["bits"] = std::string("170355f0");
    rpc.header["mediantime"] = 1700000000.0;
    bitcoin::RpcWorkSource source(rpc);

    CHECK(source.fetch_header("h").confirmations == -1);
}

TEST_CASE("RpcWorkSource::fetch_header throws on a required field missing") {
    CannedRpc rpc;
    rpc.header = json::object_t{}; // no height
    bitcoin::RpcWorkSource source(rpc);
    CHECK_THROWS_AS(source.fetch_header("h"), RpcError);
}

TEST_CASE("block_standing reports a block in the active chain without listing tips") {
    ChainRpc rpc;
    rpc.add_header(kCurrentParent, 101, 1);
    bitcoin::RpcWorkSource source(rpc);
    CHECK(source.block_standing(kCurrentParent) == bitcoin::BlockStanding::Active);
    CHECK(rpc.chaintips_calls == 0);
}

TEST_CASE("block_standing treats a block the node has never seen as pending") {
    ChainRpc rpc;
    bitcoin::RpcWorkSource source(rpc);
    CHECK(source.block_standing(kCurrentParent) == bitcoin::BlockStanding::Pending);
}

TEST_CASE("block_standing classifies the branch holding an inactive block by its tip status") {
    ChainRpc rpc;
    rpc.add_header(kCurrentParent, 101, -1);
    rpc.add_tip(kActiveTip, 100, 0, "active");
    bitcoin::BlockStanding expected = bitcoin::BlockStanding::Unknown;
    SUBCASE("invalidated") {
        rpc.add_tip(kCurrentParent, 101, 1, "invalid");
        expected = bitcoin::BlockStanding::Abandoned;
    }
    SUBCASE("validated but reorganized away") {
        rpc.add_tip(kCurrentParent, 101, 1, "valid-fork");
        expected = bitcoin::BlockStanding::Abandoned;
    }
    SUBCASE("header received, block not yet downloaded") {
        rpc.add_tip(kCurrentParent, 101, 1, "headers-only");
        expected = bitcoin::BlockStanding::Pending;
    }
    SUBCASE("block downloaded, not yet validated") {
        rpc.add_tip(kCurrentParent, 101, 1, "valid-headers");
        expected = bitcoin::BlockStanding::Pending;
    }
    bitcoin::RpcWorkSource source(rpc);
    CHECK(source.block_standing(kCurrentParent) == expected);
}

TEST_CASE("block_standing walks down to a block below its branch tip") {
    ChainRpc rpc;
    rpc.add_header(kCurrentParent, 101, -1);
    rpc.add_header(kDescendant, 102, -1, kCurrentParent);
    rpc.add_tip(kActiveTip, 100, 0, "active");
    rpc.add_tip(kDescendant, 102, 2, "invalid");
    bitcoin::RpcWorkSource source(rpc);
    CHECK(source.block_standing(kCurrentParent) == bitcoin::BlockStanding::Abandoned);
}

TEST_CASE("block_standing is unknown when no listed branch holds the block") {
    ChainRpc rpc;
    rpc.add_header(kCurrentParent, 101, -1);
    rpc.add_header(kDescendant, 102, -1, std::string(64, '4'));
    rpc.add_tip(kActiveTip, 100, 0, "active");
    rpc.add_tip(kDescendant, 102, 2, "invalid"); // a different branch at the same heights
    bitcoin::RpcWorkSource source(rpc);
    CHECK(source.block_standing(kCurrentParent) == bitcoin::BlockStanding::Unknown);
}

TEST_CASE("block_standing propagates node errors other than an unknown block") {
    CannedRpc rpc; // answers getblockheader but rejects getchaintips as unexpected
    rpc.header = json::object_t{};
    rpc.header["height"] = 101.0;
    rpc.header["confirmations"] = -1.0;
    bitcoin::RpcWorkSource source(rpc);
    CHECK_THROWS_AS(static_cast<void>(source.block_standing(kCurrentParent)), RpcError);
}

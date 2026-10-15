// IPC supplies complete templates. RPC remains authoritative for the tip and every other
// operation, and supplies work while IPC reconnects.
#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "bitcoin/mining_ipc_client.hpp"
#include "bitcoin/rpc_client.hpp"
#include "bitcoin/work_source_ipc.hpp"
#include "bitcoin/work_source_rpc.hpp"
#include "core/errors.hpp"
#include "util/block_header.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::bitcoin;

namespace {

const std::string kRpcTip(64, 'b');

std::string rpc_template_body(std::string_view previous_block_hash, int64_t height = 171) {
    return R"({"result":{"height":)" + std::to_string(height) +
           R"(,"version":536870912,"curtime":1700000000,)" +
           R"("bits":"207fffff","coinbasevalue":5000000000,"previousblockhash":")" +
           std::string(previous_block_hash) + R"(","transactions":[]},"error":null,"id":1})";
}

class FakeMiningClient final : public MiningIpcClient {
public:
    BlockTemplate block_template;
    bool is_available = true;
    bool fail_template = false;
    int creates = 0;
    int interrupts = 0;

    bool available() const noexcept override { return is_available; }

    BlockTemplate create_block() override {
        ++creates;
        if (fail_template) {
            is_available = false;
            throw std::runtime_error("template failed");
        }
        return block_template;
    }

    void interrupt() noexcept override {
        is_available = false;
        ++interrupts;
    }
};

class FakeRpc final : public RpcClient {
public:
    FakeRpc() : RpcClient("http://rpc", "user", "password", 1) {}

    std::string tip = kRpcTip;
    std::string chain = "regtest";
    bool initial_block_download = false;
    int connection_count = 1;
    bool fail_chain_info = false;
    bool fail_connections = false;
    bool fail_template = false;
    std::function<void()> on_chain_info;
    int64_t tip_confirmations = 1;
    int template_requests = 0;
    int connection_requests = 0;

protected:
    std::string post_one(const Resolved&, const std::string& payload, long,
                         long* http_status) override {
        if (http_status)
            *http_status = 200;
        if (payload.find("getbestblockhash") != std::string::npos)
            return R"({"result":")" + tip + R"(","error":null,"id":1})";
        if (payload.find("getblockchaininfo") != std::string::npos) {
            if (on_chain_info)
                on_chain_info();
            if (fail_chain_info)
                throw RpcError("getblockchaininfo permission denied", -32601);
            return R"({"result":{"chain":")" + chain +
                   R"(","blocks":170,"bestblockhash":")" + tip +
                   R"(","initialblockdownload":)" +
                   (initial_block_download ? "true" : "false") +
                   R"(},"error":null,"id":1})";
        }
        if (payload.find("getconnectioncount") != std::string::npos) {
            ++connection_requests;
            if (fail_connections)
                throw RpcError("getconnectioncount permission denied", -32601);
            return R"({"result":)" + std::to_string(connection_count) +
                   R"(,"error":null,"id":1})";
        }
        if (payload.find("getblockheader") != std::string::npos)
            return R"({"result":{"height":170,"confirmations":)" +
                   std::to_string(tip_confirmations) +
                   R"(,"bits":"207fffff","mediantime":1700000000},"error":null,"id":1})";
        if (payload.find("submitblock") != std::string::npos)
            return R"({"result":null,"error":null,"id":1})";
        if (payload.find("getblocktemplate") != std::string::npos) {
            ++template_requests;
            if (fail_template)
                throw RpcError("getblocktemplate permission denied", -32601);
            return rpc_template_body(std::string(64, 'a'));
        }
        throw std::runtime_error("unexpected RPC request");
    }
};

class FailbackRpc final : public RpcClient {
public:
    FailbackRpc()
        : RpcClient(std::vector<RpcEndpoint>{{"http://primary", "user", "password"},
                                             {"http://backup", "user", "password"}},
                    1) {}

    bool primary_available = false;
    bool primary_template_available = true;
    const std::string tip = std::string(64, 'a');
    int primary_template_requests = 0;
    int backup_template_requests = 0;

    void advance_time(double seconds) {
        now_seconds_.fetch_add(seconds, std::memory_order_relaxed);
    }

protected:
    double steady_now_seconds() const override {
        return now_seconds_.load(std::memory_order_relaxed);
    }

    std::string post_one(const Resolved& endpoint, const std::string& payload, long,
                         long* http_status) override {
        if (http_status)
            *http_status = 200;
        if (endpoint.url == "http://primary" && !primary_available)
            throw RpcConnectError("primary unavailable");
        if (payload.find("getbestblockhash") != std::string::npos)
            return R"({"result":")" + tip + R"(","error":null,"id":1})";
        if (payload.find("getblockchaininfo") != std::string::npos)
            return R"({"result":{"chain":"regtest","blocks":170,"bestblockhash":")" +
                   tip + R"("},"error":null,"id":1})";
        if (payload.find("getblocktemplate") != std::string::npos) {
            if (endpoint.url == "http://primary") {
                ++primary_template_requests;
                if (!primary_template_available)
                    throw RpcConnectError("primary cannot serve a template");
            } else {
                ++backup_template_requests;
            }
            return rpc_template_body(tip);
        }
        if (payload.find("getblockheader") != std::string::npos)
            return R"({"result":{"height":170,"confirmations":1,"bits":"207fffff",)"
                   R"("mediantime":1700000000},"error":null,"id":1})";
        throw std::runtime_error("unexpected RPC request");
    }

private:
    std::atomic<double> now_seconds_{0.0};
};

class ReadinessRpc final : public RpcClient {
public:
    ReadinessRpc()
        : RpcClient(std::vector<RpcEndpoint>{{"http://primary", "user", "password"},
                                             {"http://backup", "user", "password"}}, 1) {}

    bool primary_initial_download = false;
    int primary_connections = 1;
    bool primary_connection_error = false;
    const std::string primary_tip = std::string(64, 'a');
    const std::string backup_tip = std::string(64, 'b');
    int primary_template_requests = 0;
    int backup_template_requests = 0;
    int backup_readiness_requests = 0;

protected:
    std::string post_one(const Resolved& endpoint, const std::string& payload, long,
                         long* http_status) override {
        if (http_status)
            *http_status = 200;
        const bool primary = endpoint.url == "http://primary";
        const std::string& tip = primary ? primary_tip : backup_tip;
        const int height = primary ? 170 : 180;
        if (payload.find("getblockchaininfo") != std::string::npos) {
            if (!primary)
                ++backup_readiness_requests;
            return R"({"result":{"chain":"main","blocks":)" + std::to_string(height) +
                   R"(,"bestblockhash":")" + tip + R"(","initialblockdownload":)" +
                   (primary && primary_initial_download ? "true" : "false") +
                   R"(},"error":null,"id":1})";
        }
        if (payload.find("getconnectioncount") != std::string::npos) {
            if (!primary)
                ++backup_readiness_requests;
            if (primary && primary_connection_error)
                throw RpcConnectError("primary peer query unavailable");
            return R"({"result":)" + std::to_string(primary ? primary_connections : 1) +
                   R"(,"error":null,"id":1})";
        }
        if (payload.find("getblocktemplate") != std::string::npos) {
            if (primary) {
                ++primary_template_requests;
                if (primary_initial_download)
                    throw RpcError("initial block download", -10);
                if (primary_connections == 0)
                    throw RpcError("not connected", -9);
            } else {
                ++backup_template_requests;
            }
            return rpc_template_body(tip, height + 1);
        }
        throw std::runtime_error("unexpected RPC request");
    }
};

class BlockingMiningClient final : public MiningIpcClient {
public:
    bool available() const noexcept override { return !stopped.load(std::memory_order_acquire); }

    BlockTemplate create_block() override {
        std::unique_lock<std::mutex> lock(mutex);
        entered = true;
        cv.notify_all();
        cv.wait(lock, [this] { return stopped.load(std::memory_order_acquire); });
        throw std::runtime_error("interrupted");
    }

    void interrupt() noexcept override {
        stopped.store(true, std::memory_order_release);
        cv.notify_all();
    }

    void wait_until_entered() {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return entered; });
    }

private:
    std::atomic<bool> stopped{false};
    std::mutex mutex;
    std::condition_variable cv;
    bool entered = false;
};

struct Sources {
    FakeMiningClient ipc;
    FakeRpc rpc;
    RpcWorkSource rpc_source{rpc};
    IpcWorkSource source{ipc, rpc_source, "ipc:///tmp/mining.sock"};
};

Bytes dummy_coinbase() {
    return util::from_hex(
        "01000000" // version
        "01"       // one input
        "0000000000000000000000000000000000000000000000000000000000000000ffffffff"
        "03" "02aa00" // scriptSig
        "ffffffff"    // sequence
        "01"          // one output
        "00f2052a01000000" "01" "51"
        "00000000"); // locktime
}

Bytes witness_transaction() {
    return util::from_hex(
        "02000000" "0001" // version, witness marker and flag
        "01"              // one input
        "1111111111111111111111111111111111111111111111111111111111111111"
        "00000000" // prevout index
        "00"       // empty scriptSig
        "feffffff" // sequence
        "01"       // one output
        "0100000000000000" "01" "51"
        "01" "02" "aabb" // one witness item
        "00000000");     // locktime
}

Bytes serialized_block(ByteView transaction_count, ByteView transaction) {
    Bytes block(util::kHeaderSize, 0);
    append(block, transaction_count);
    append(block, dummy_coinbase());
    append(block, transaction);
    return block;
}

} // namespace

TEST_CASE("IpcWorkSource uses IPC only for templates") {
    Sources sources;
    sources.ipc.block_template.height = 171;
    sources.ipc.block_template.previousblockhash = kRpcTip;

    CHECK(sources.source.get_tip() == kRpcTip);
    CHECK(sources.source.fetch_template().height == 171);

    const ChainInfo chain = sources.source.detect_chain();
    CHECK(chain.chain == "regtest");
    CHECK(chain.blocks == 170);

    const HeaderFacts header = sources.source.fetch_header("hash");
    CHECK(header.height == 170);
    CHECK(header.confirmations == 1);
    CHECK(header.bits_hex == "207fffff");
    CHECK_FALSE(sources.source.submit_block_hex("00").has_value());
}

TEST_CASE("IpcWorkSource returns a valid failback template then resumes IPC") {
    FakeMiningClient ipc;
    FailbackRpc rpc;
    RpcWorkSource rpc_source{rpc};
    IpcWorkSource source{ipc, rpc_source, "ipc:///tmp/mining.sock"};
    ipc.block_template.height = 171;
    ipc.block_template.previousblockhash = rpc.tip;

    CHECK(rpc.getbestblockhash() == rpc.tip);
    CHECK(source.fetch_template().previousblockhash == rpc.tip);
    CHECK(ipc.creates == 1);
    CHECK(source.active_index() == 0);
    REQUIRE(rpc.active_index() == 1);

    rpc.primary_available = true;
    source.maybe_failback(rpc.tip);
    CHECK(rpc.active_index() == 1);
    CHECK(rpc.primary_template_requests == 0);
    rpc.advance_time(RpcClient::kConnectionCooldownSeconds);
    source.maybe_failback(rpc.tip);

    CHECK(source.fetch_template().previousblockhash == rpc.tip);
    CHECK(rpc.active_index() == 0);
    CHECK(ipc.creates == 1);
    CHECK(rpc.primary_template_requests == 1);
    CHECK(rpc.backup_template_requests == 0);
    CHECK(source.active_index() == 1);

    CHECK(source.fetch_template().previousblockhash == rpc.tip);
    CHECK(ipc.creates == 2);
    CHECK(source.active_index() == 0);
}

TEST_CASE("a failed RPC failback candidate continues IPC without fetching from the backup") {
    FakeMiningClient ipc;
    FailbackRpc rpc;
    RpcWorkSource rpc_source{rpc};
    IpcWorkSource source{ipc, rpc_source, "ipc:///tmp/mining.sock"};
    ipc.block_template.height = 171;
    ipc.block_template.previousblockhash = rpc.tip;

    CHECK(rpc.getbestblockhash() == rpc.tip);
    CHECK(source.fetch_template().previousblockhash == rpc.tip);
    REQUIRE(rpc.active_index() == 1);
    REQUIRE(ipc.creates == 1);

    rpc.primary_available = true;
    rpc.primary_template_available = false;
    source.maybe_failback(rpc.tip);
    CHECK(rpc.primary_template_requests == 0);
    rpc.advance_time(RpcClient::kConnectionCooldownSeconds);
    source.maybe_failback(rpc.tip);

    CHECK(source.fetch_template().previousblockhash == rpc.tip);
    CHECK(rpc.active_index() == 1);
    CHECK(ipc.creates == 2);
    CHECK(rpc.primary_template_requests == 1);
    CHECK(rpc.backup_template_requests == 0);
    CHECK(source.active_index() == 0);

    CHECK(source.fetch_template().previousblockhash == rpc.tip);
    CHECK(ipc.creates == 3);
    CHECK(rpc.primary_template_requests == 1);
}

TEST_CASE("an IPC template on a different tip falls back for that cycle without reconnecting") {
    Sources sources;
    sources.ipc.block_template.height = 171;
    sources.ipc.block_template.previousblockhash = kRpcTip;
    CHECK(sources.source.fetch_template().previousblockhash == kRpcTip);
    CHECK(sources.source.active_index() == 0);

    sources.ipc.block_template.previousblockhash = "stale-tip";

    CHECK(sources.source.fetch_template().height == 171);
    CHECK(sources.source.active_index() == 1);
    CHECK(sources.ipc.available());
    CHECK(sources.source.endpoint_urls() ==
          std::vector<std::string>{"ipc:///tmp/mining.sock", "http://rpc"});

    // Once IPC agrees with the tip again its template is used, with no restart needed.
    sources.ipc.block_template.previousblockhash = kRpcTip;
    CHECK(sources.source.fetch_template().previousblockhash == kRpcTip);
    CHECK(sources.source.active_index() == 0);
}

TEST_CASE("IPC request failure uses RPC until a fresh session becomes available") {
    Sources sources;
    sources.ipc.fail_template = true;

    const BlockTemplate block_template = sources.source.fetch_template();
    CHECK(block_template.height == 171);
    CHECK(block_template.previousblockhash == std::string(64, 'a'));
    CHECK(sources.source.active_index() == 1);
    CHECK(sources.ipc.creates == 1);

    // Reconnect runs outside IpcWorkSource. While it is pending, fetches go directly to RPC.
    CHECK(sources.source.fetch_template().height == 171);
    CHECK(sources.ipc.creates == 1);

    // A fully bootstrapped replacement session is tried and promoted only on the current tip.
    sources.ipc.fail_template = false;
    sources.ipc.is_available = true;
    sources.ipc.block_template.height = 171;
    sources.ipc.block_template.previousblockhash = kRpcTip;
    CHECK(sources.source.fetch_template().height == 171);
    CHECK(sources.source.active_index() == 0);
    CHECK(sources.ipc.creates == 2);
}

TEST_CASE("a reconnected IPC session stays inactive until its template is current") {
    Sources sources;
    sources.ipc.is_available = false;
    CHECK(sources.source.fetch_template().height == 171);
    CHECK(sources.source.active_index() == 1);
    CHECK(sources.ipc.creates == 0);

    sources.ipc.is_available = true;
    sources.ipc.block_template.previousblockhash = "stale-tip";
    CHECK(sources.source.fetch_template().height == 171);
    CHECK(sources.source.active_index() == 1);

    sources.ipc.block_template.height = 171;
    sources.ipc.block_template.previousblockhash = kRpcTip;
    CHECK(sources.source.fetch_template().height == 171);
    CHECK(sources.source.active_index() == 0);
}

TEST_CASE("an IPC template height must follow the authoritative RPC tip height") {
    Sources sources;
    sources.ipc.block_template.height = 171;
    sources.ipc.block_template.previousblockhash = kRpcTip;
    CHECK(sources.source.fetch_template().height == 171);
    CHECK(sources.source.active_index() == 0);

    // A future template producer may stop encoding height - 1 in the coinbase locktime.
    sources.ipc.block_template.height = 1;
    const BlockTemplate fallback = sources.source.fetch_template();
    CHECK(fallback.height == 171);
    CHECK(fallback.previousblockhash == std::string(64, 'a'));
    CHECK(sources.source.active_index() == 1);

    sources.ipc.block_template.height = 171;
    CHECK(sources.source.fetch_template().height == 171);
    CHECK(sources.source.active_index() == 0);
}

TEST_CASE("a tip change during IPC validation falls back for that cycle") {
    Sources sources;
    sources.ipc.block_template.height = 171;
    sources.ipc.block_template.previousblockhash = kRpcTip;
    CHECK(sources.source.fetch_template().previousblockhash == kRpcTip);
    CHECK(sources.source.active_index() == 0);

    sources.rpc.tip = std::string(64, 'c');
    CHECK(sources.source.fetch_template().previousblockhash == std::string(64, 'a'));
    CHECK(sources.source.active_index() == 1);
    CHECK(sources.ipc.available());

    sources.rpc.tip = kRpcTip;
    CHECK(sources.source.fetch_template().previousblockhash == kRpcTip);
    CHECK(sources.source.active_index() == 0);
}

TEST_CASE("IpcWorkSource forwards shutdown interruption") {
    Sources sources;
    sources.source.interrupt();
    CHECK(sources.ipc.interrupts == 1);
    sources.source.interrupt();
    CHECK(sources.ipc.interrupts == 1);
}

TEST_CASE("mainnet IPC requires a synced connected RPC tip") {
    Sources sources;
    sources.rpc.chain = "main";
    sources.ipc.block_template.height = 171;
    sources.ipc.block_template.previousblockhash = kRpcTip;

    CHECK(sources.source.fetch_template().previousblockhash == kRpcTip);
    CHECK(sources.source.active_index() == 0);
    CHECK(sources.rpc.connection_requests == 1);
    CHECK(sources.rpc.template_requests == 0);
}

TEST_CASE("IPC preserves Core's test-chain readiness exemption") {
    for (const std::string chain : {"regtest", "test", "testnet4"}) {
        CAPTURE(chain);
        Sources sources;
        sources.rpc.chain = chain;
        sources.rpc.initial_block_download = true;
        sources.rpc.connection_count = 0;
        sources.ipc.block_template.height = 171;
        sources.ipc.block_template.previousblockhash = kRpcTip;

        CHECK(sources.source.fetch_template().previousblockhash == kRpcTip);
        CHECK(sources.source.active_index() == 0);
        CHECK(sources.rpc.connection_requests == 0);
        CHECK(sources.rpc.template_requests == 0);
    }
}

TEST_CASE("unready mainnet IPC falls back to a ready backup then recovers") {
    FakeMiningClient ipc;
    ReadinessRpc rpc;
    RpcWorkSource rpc_source{rpc};
    IpcWorkSource source{ipc, rpc_source, "ipc:///tmp/mining.sock"};
    ipc.block_template.height = 171;
    ipc.block_template.previousblockhash = rpc.primary_tip;
    SUBCASE("initial block download") { rpc.primary_initial_download = true; }
    SUBCASE("no peers") { rpc.primary_connections = 0; }

    const auto fallback = source.fetch_template();
    CHECK(fallback.height == 181);
    CHECK(fallback.previousblockhash == rpc.backup_tip);
    CHECK(rpc.primary_template_requests == 1);
    CHECK(rpc.backup_template_requests == 1);
    CHECK(rpc.active_index() == 1);
    CHECK(source.active_index() == 2);
    CHECK(ipc.available());

    CHECK(source.fetch_template().previousblockhash == rpc.backup_tip);
    CHECK(rpc.backup_template_requests == 2);
    CHECK(source.active_index() == 2);

    ipc.block_template.height = 181;
    ipc.block_template.previousblockhash = rpc.backup_tip;
    CHECK(source.fetch_template().previousblockhash == rpc.backup_tip);
    CHECK(source.active_index() == 0);
    CHECK(rpc.backup_template_requests == 2);
}

TEST_CASE("mining readiness never mixes answers from different RPC endpoints") {
    ReadinessRpc rpc;
    rpc.primary_connection_error = true;

    CHECK_THROWS_AS(rpc.get_mining_tip(), RpcConnectionError);
    CHECK(rpc.active_index() == 0);
    CHECK(rpc.backup_readiness_requests == 0);
}

TEST_CASE("IPC validation failures fall back once and retry IPC without reconnecting") {
    Sources sources;
    sources.rpc.chain = "main";
    sources.ipc.block_template.height = 171;
    sources.ipc.block_template.previousblockhash = kRpcTip;
    SUBCASE("chain information unavailable") { sources.rpc.fail_chain_info = true; }
    SUBCASE("peer information unavailable") { sources.rpc.fail_connections = true; }

    CHECK(sources.source.fetch_template().previousblockhash == std::string(64, 'a'));
    CHECK(sources.rpc.template_requests == 1);
    CHECK(sources.source.active_index() == 1);
    CHECK(sources.ipc.available());

    sources.rpc.fail_template = true;
    CHECK_THROWS_AS(sources.source.fetch_template(), RpcError);
    CHECK(sources.rpc.template_requests == 2);

    sources.rpc.fail_chain_info = false;
    sources.rpc.fail_connections = false;
    CHECK(sources.source.fetch_template().previousblockhash == kRpcTip);
    CHECK(sources.rpc.template_requests == 2);
    CHECK(sources.source.active_index() == 0);
}

TEST_CASE("shutdown during IPC validation starts no final RPC template request") {
    Sources sources;
    sources.ipc.block_template.height = 171;
    sources.ipc.block_template.previousblockhash = kRpcTip;
    sources.rpc.on_chain_info = [&] { sources.source.interrupt(); };
    SUBCASE("validation succeeds") {}
    SUBCASE("validation fails") { sources.rpc.fail_chain_info = true; }

    CHECK_THROWS(sources.source.fetch_template());
    CHECK(sources.rpc.template_requests == 0);
    CHECK(sources.source.active_index() == 1);
}

TEST_CASE("shutdown interrupts IPC without starting a final RPC template call") {
    BlockingMiningClient ipc;
    FakeRpc rpc;
    RpcWorkSource rpc_source{rpc};
    IpcWorkSource source{ipc, rpc_source, "ipc:///tmp/mining.sock"};
    std::exception_ptr failure;

    std::jthread fetcher([&] {
        try {
            static_cast<void>(source.fetch_template());
        } catch (...) {
            failure = std::current_exception();
        }
    });
    ipc.wait_until_entered();
    source.interrupt();
    fetcher.join();

    CHECK(failure != nullptr);
    CHECK(rpc.template_requests == 0);
    CHECK(source.active_index() == 1);
}

TEST_CASE("fill_block_fields strips Core's dummy coinbase and preserves witness transactions") {
    const Bytes transaction = witness_transaction();
    Bytes block = serialized_block(Bytes{2}, transaction);
    block[util::kVersionOffset + 3] = 0x20;
    for (size_t index = 0; index < util::kMerkleOffset - util::kPrevhashOffset; ++index)
        block[util::kPrevhashOffset + index] = static_cast<uint8_t>(index + 1);
    std::fill_n(block.begin() + util::kMerkleOffset,
                util::kTimeOffset - util::kMerkleOffset, uint8_t{0xaa});
    block[util::kTimeOffset] = 0x78;
    block[util::kTimeOffset + 1] = 0x56;
    block[util::kTimeOffset + 2] = 0x34;
    block[util::kTimeOffset + 3] = 0x12;
    block[util::kBitsOffset] = 0x19;
    block[util::kBitsOffset + 1] = 0x42;
    block[util::kBitsOffset + 2] = 0x03;
    block[util::kBitsOffset + 3] = 0x17;

    BlockTemplate block_template;
    fill_block_fields(block_template, block);

    CHECK(block_template.txn_count == 1);
    CHECK(block_template.txn_data == transaction);
    CHECK(block_template.version == 0x20000000u);
    CHECK(block_template.curtime == 0x12345678u);
    CHECK(block_template.bits == 0x17034219u);
    CHECK(block_template.bits_hex == "17034219");
    CHECK(block_template.previousblockhash ==
          "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201");
}

TEST_CASE("fill_block_fields rejects malformed serialized blocks") {
    SUBCASE("zero transactions") {
        Bytes block(util::kHeaderSize, 0);
        block.push_back(0);
        BlockTemplate block_template;
        CHECK_THROWS_AS(fill_block_fields(block_template, block), std::invalid_argument);
    }
    SUBCASE("non-canonical transaction count") {
        const Bytes block = serialized_block(Bytes{0xfd, 0x02, 0x00}, witness_transaction());
        BlockTemplate block_template;
        CHECK_THROWS_AS(fill_block_fields(block_template, block), std::invalid_argument);
    }
    SUBCASE("truncated dummy coinbase") {
        Bytes block(util::kHeaderSize, 0);
        block.push_back(1);
        append(block, ByteView(dummy_coinbase()).first(10));
        BlockTemplate block_template;
        CHECK_THROWS_AS(fill_block_fields(block_template, block), std::invalid_argument);
    }
}

TEST_CASE("parse_coinbase_output validates and decodes a serialized CTxOut") {
    const CoinbaseOutput output =
        parse_coinbase_output(util::from_hex("070605040302010003aabbcc"));
    CHECK(output.value == 0x0001020304050607ULL);
    CHECK(util::to_hex(output.script) == "aabbcc");

    for (const char* malformed :
         {"", "0000000000000000", "0000000000000000fd0100aa",
          "000000000000000002aa", "000000000000000001aabb",
          "ffffffffffffffff00"}) {
        CHECK_THROWS_AS(parse_coinbase_output(util::from_hex(malformed)),
                        std::invalid_argument);
    }
}

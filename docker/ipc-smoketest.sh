#!/usr/bin/env bash
#
# Live Bitcoin Core v31.1 IPC smoke test. The pool's RPC user cannot call getblocktemplate, so
# accepted work and recovery after restarting Core prove every template came through IPC.
#
# Run from the repository root:
#   bash docker/ipc-smoketest.sh
#
set -euo pipefail

export MSYS_NO_PATHCONV=1

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })}"
BITCOIND_IMAGE=erikslund-bitcoind:ipc-smoke
TOOLCHAIN_IMAGE=erikslund-pool-build
MINER_IMAGE=erikslund-miner:ipc-smoke
BITCOIND=ep-ipc-smoke-bitcoind
POOL=ep-ipc-smoke-pool
MINER=ep-ipc-smoke-miner
NETWORK=ep-ipc-smoke
BUILD_VOLUME=ep-ipc-smoke-build
DATA_VOLUME=ep-ipc-smoke-data
SOCKET_VOLUME=ep-ipc-smoke-socket
MINING_ADDRESS=bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf
POOL_RPC_METHODS=getblockchaininfo,getconnectioncount,getbestblockhash,getblockheader,getchaintips,submitblock
POOL_RPC_METHODS+=,getblockcount,getblockhash,getblock,getblockstats
POOL_RPC_METHODS+=,createwallet,loadwallet,getnewaddress,sendtoaddress
POOL_RPC_METHODS+=,generatetoaddress,getrawmempool
POOL_RPC_METHODS+=,getrawtransaction,decoderawtransaction
KEEP="${KEEP:-0}"

reset_resources() {
    docker rm -f "$MINER" "$POOL" "$BITCOIND" >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
    docker volume rm "$BUILD_VOLUME" "$DATA_VOLUME" "$SOCKET_VOLUME" >/dev/null 2>&1 || true
}

cleanup() {
    if [ "$KEEP" = "1" ]; then
        echo "KEEP=1: leaving $BITCOIND and $POOL running on network $NETWORK"
        return
    fi
    reset_resources
}

fail() {
    echo "FAIL: $*" >&2
    docker logs "$MINER" 2>&1 | tail -40 >&2 || true
    docker logs "$POOL" 2>&1 | head -40 >&2 || true
    docker logs "$POOL" 2>&1 | tail -40 >&2 || true
    docker logs "$BITCOIND" 2>&1 | tail -40 >&2 || true
    exit 1
}

pool_cli() {
    docker exec "$BITCOIND" bitcoin-cli -regtest -rpcconnect=127.0.0.1 -rpcport=18443 \
        -rpcuser=erikslund -rpcpassword=erikslundpass "$@"
}

pool_get() {
    docker run --rm --network "$NETWORK" --entrypoint curl "$TOOLCHAIN_IMAGE" \
        -fsS --max-time 2 "http://$POOL:7777$1"
}

json_integer() {
    local body="$1"
    local key="$2"
    sed -n "s/.*\"$key\":[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" <<<"$body"
}

ipc_is_active() {
    pool_get /metrics 2>/dev/null |
        grep -Fq 'erikslundpool_bitcoind_node_active{url="ipc:///ipc/mining.sock"} 1'
}

rpc_is_active() {
    pool_get /metrics 2>/dev/null |
        grep -Fq 'erikslundpool_bitcoind_node_active{url="http://bitcoind:18443"} 1'
}

wait_for_job() {
    local expected_height="$1"
    local minimum_jobs="$2"
    local minimum_transactions="${3:-0}"
    local stats
    local height
    local jobs
    local transactions
    for _ in $(seq 1 60); do
        stats="$(pool_get /stats/stratifier 2>/dev/null || true)"
        height="$(json_integer "$stats" height)"
        jobs="$(json_integer "$stats" jobs_created)"
        transactions="$(json_integer "$stats" txns_in_job)"
        if [ "$height" = "$expected_height" ] && [ -n "$jobs" ] &&
                [ "$jobs" -ge "$minimum_jobs" ] && [ -n "$transactions" ] &&
                [ "$transactions" -ge "$minimum_transactions" ] && ipc_is_active; then
            printf '%s\n' "$jobs"
            return 0
        fi
        sleep 1
    done
    return 1
}

trap cleanup EXIT
reset_resources

echo "==> 1/9 build Bitcoin Core v31.1, the C++ pool, and the CPU test miner"
docker build -q -t "$BITCOIND_IMAGE" -f "$REPO_ROOT/tools/regtest/Dockerfile.bitcoind" \
    "$REPO_ROOT/tools/regtest" >/dev/null
docker build -q -t "$TOOLCHAIN_IMAGE" "$REPO_ROOT/docker" >/dev/null
docker build -q -t "$MINER_IMAGE" -f "$REPO_ROOT/tools/regtest/Dockerfile.miner" \
    "$REPO_ROOT/tools/regtest" >/dev/null
docker volume create "$BUILD_VOLUME" >/dev/null
docker run --rm -v "$REPO_ROOT:/src:ro" \
    -v "$BUILD_VOLUME:/build" \
    "$TOOLCHAIN_IMAGE" >/tmp/erikslund-ipc-build.log 2>&1 ||
    { tail -40 /tmp/erikslund-ipc-build.log >&2; fail "C++ build or unit tests failed"; }

echo "==> 2/9 start Bitcoin Core's v31.1 multiprocess node"
docker network create "$NETWORK" >/dev/null
docker volume create "$DATA_VOLUME" >/dev/null
docker volume create "$SOCKET_VOLUME" >/dev/null
docker run -d --name "$BITCOIND" --hostname bitcoind --network "$NETWORK" \
    --security-opt no-new-privileges:true --cap-drop ALL --read-only --tmpfs /tmp \
    --pids-limit 256 --memory 2g --cpus 2 \
    -v "$REPO_ROOT/tools/regtest/bitcoin.conf:/etc/bitcoin/bitcoin.conf:ro" \
    -v "$DATA_VOLUME:/data" -v "$SOCKET_VOLUME:/ipc" \
    --entrypoint bitcoin "$BITCOIND_IMAGE" -m node \
    -conf=/etc/bitcoin/bitcoin.conf -datadir=/data \
    -ipcbind=unix:/ipc/mining.sock -rpcwhitelistdefault=0 \
    "-rpcwhitelist=erikslund:$POOL_RPC_METHODS" \
    >/dev/null

for _ in $(seq 1 60); do
    if pool_cli getblockchaininfo >/dev/null 2>&1 &&
            docker exec "$BITCOIND" sh -c 'test -S /ipc/mining.sock'; then
        break
    fi
    sleep 1
done
pool_cli getblockchaininfo >/dev/null 2>&1 || fail "Bitcoin Core RPC did not become ready"
docker exec "$BITCOIND" sh -c 'test -S /ipc/mining.sock' ||
    fail "Bitcoin Core IPC socket did not become ready"

echo "==> 3/9 prove RPC fallback cannot fetch templates and create a fee-paying transaction"
RPC_DENIAL="$(pool_cli getblocktemplate 2>&1 || true)"
[[ "$RPC_DENIAL" == *"403"* ]] || fail "pool RPC user was not denied getblocktemplate"
# Mine enough wallet-owned blocks to mature a coinbase, then spend it to another native witness
# address. This gives the IPC template both a real fee and a witness commitment to preserve.
pool_cli createwallet ipc-smoke >/dev/null
WALLET_ADDRESS="$(pool_cli -rpcwallet=ipc-smoke getnewaddress)"
pool_cli generatetoaddress 101 "$WALLET_ADDRESS" >/dev/null
RECIPIENT="$(pool_cli -rpcwallet=ipc-smoke getnewaddress)"
FEE_TXID="$(pool_cli -rpcwallet=ipc-smoke sendtoaddress "$RECIPIENT" 1)"
[[ "$(pool_cli getrawmempool)" == *"$FEE_TXID"* ]] ||
    fail "fee-paying witness transaction did not enter the mempool"

echo "==> 4/9 start the pool and require a transaction-bearing IPC template"
START_HEIGHT="$(pool_cli getblockcount)"
docker run -d --name "$POOL" --hostname pool --network "$NETWORK" --user 1000:1000 \
    --security-opt no-new-privileges:true --cap-drop ALL --read-only --tmpfs /tmp \
    --pids-limit 512 --memory 1g --cpus 2 \
    -v "$BUILD_VOLUME:/build:ro" \
    -v "$REPO_ROOT/docker/ipc-regtest.yml:/cfg/pool.yml:ro" \
    -v "$SOCKET_VOLUME:/ipc" --entrypoint /build/cmake/erikslund-pool \
    "$TOOLCHAIN_IMAGE" --config /cfg/pool.yml >/dev/null

FIRST_JOBS="$(wait_for_job "$((START_HEIGHT + 1))" 1 1)" ||
    fail "IPC did not include the fee-paying mempool transaction"
echo "    IPC job $FIRST_JOBS mines height $((START_HEIGHT + 1)) with a mempool transaction"

echo "==> 5/9 solve the IPC job through Stratum and require Core to accept it"
docker run -d --name "$MINER" --network "$NETWORK" --read-only --tmpfs /tmp \
    --security-opt no-new-privileges:true --cap-drop ALL --pids-limit 128 --memory 256m --cpus 1 \
    "$MINER_IMAGE" --algo sha256d --url "stratum+tcp://$POOL:3333" \
    --user "$MINING_ADDRESS" --pass x --threads 1 --retry-pause 1 >/dev/null
SOLVED_HEIGHT=
for _ in $(seq 1 600); do
    SOLVED_HEIGHT="$(pool_cli getblockcount)"
    if [ "$SOLVED_HEIGHT" -gt "$START_HEIGHT" ]; then
        break
    fi
    sleep 0.1
done
[ -n "$SOLVED_HEIGHT" ] && [ "$SOLVED_HEIGHT" -gt "$START_HEIGHT" ] ||
    fail "the pool did not submit an accepted IPC block"
docker rm -f "$MINER" >/dev/null 2>&1 || true

echo "==> 6/9 verify the accepted block included the transaction and claimed its fee"
SOLVED_HASH="$(pool_cli getblockhash "$((START_HEIGHT + 1))")"
SOLVED_BLOCK="$(pool_cli getblock "$SOLVED_HASH" 2)"
[[ "$SOLVED_BLOCK" == *"$FEE_TXID"* ]] ||
    fail "accepted block omitted the fee-paying transaction"
SOLVED_COINBASE_TXID="$(sed -n '/\"tx\": \[/,$ { /\"txid\":/ { s/.*\"txid\": \"\([0-9a-f]\{64\}\)\".*/\1/p; q; } }' \
    <<<"$SOLVED_BLOCK")"
SOLVED_COINBASE_RAW="$(pool_cli getrawtransaction "$SOLVED_COINBASE_TXID" false "$SOLVED_HASH")"
SOLVED_COINBASE="$(pool_cli decoderawtransaction "$SOLVED_COINBASE_RAW")"
COINBASE_SATS="$(awk '/"value":/ { value=$2; gsub(/,/, "", value); total += value * 100000000 }
    END { printf "%.0f", total }' <<<"$SOLVED_COINBASE")"
REWARD_STATS="$(pool_cli getblockstats "$SOLVED_HASH" \
    '["subsidy","totalfee"]')"
SUBSIDY="$(json_integer "$REWARD_STATS" subsidy)"
TOTAL_FEE="$(json_integer "$REWARD_STATS" totalfee)"
[ -n "$SUBSIDY" ] && [ -n "$TOTAL_FEE" ] && [ "$TOTAL_FEE" -gt 0 ] ||
    fail "accepted block did not report a positive transaction fee"
[ "$COINBASE_SATS" -eq "$((SUBSIDY + TOTAL_FEE))" ] ||
    fail "coinbase claimed $COINBASE_SATS sats, expected subsidy plus fees ($((SUBSIDY + TOTAL_FEE)))"

SECOND_JOBS="$(wait_for_job "$((SOLVED_HEIGHT + 1))" "$((FIRST_JOBS + 1))")" ||
    fail "IPC did not supply a new job after the tip advanced"
echo "    IPC job $SECOND_JOBS mines height $((SOLVED_HEIGHT + 1))"

echo "==> 7/9 restart Core and force the live IPC session to fail"
POOL_PID="$(docker inspect --format '{{.State.Pid}}' "$POOL")"
docker restart "$BITCOIND" >/dev/null
for _ in $(seq 1 60); do
    if pool_cli getblockchaininfo >/dev/null 2>&1 &&
            docker exec "$BITCOIND" sh -c 'test -S /ipc/mining.sock'; then
        break
    fi
    sleep 1
done
pool_cli getblockchaininfo >/dev/null 2>&1 || fail "Bitcoin Core RPC did not recover"
docker exec "$BITCOIND" sh -c 'test -S /ipc/mining.sock' ||
    fail "Bitcoin Core IPC socket did not recover"

# Advance the tip outside the pool so refresh_work must call the now-broken IPC capability.
pool_cli -rpcwallet=ipc-smoke getnewaddress >/dev/null 2>&1 ||
    { pool_cli loadwallet ipc-smoke >/dev/null; }
pool_cli -rpcwallet=ipc-smoke generatetoaddress 1 "$WALLET_ADDRESS" >/dev/null
RECOVERY_HEIGHT="$(pool_cli getblockcount)"
RECOVERY_RECIPIENT="$(pool_cli -rpcwallet=ipc-smoke getnewaddress)"
RECOVERY_TXID="$(pool_cli -rpcwallet=ipc-smoke sendtoaddress "$RECOVERY_RECIPIENT" 1)"
[[ "$(pool_cli getrawmempool)" == *"$RECOVERY_TXID"* ]] ||
    fail "recovery fee transaction did not enter the mempool"

echo "==> 8/9 require RPC fallback, then a fresh transaction-bearing IPC job"
for _ in $(seq 1 30); do
    POOL_LOGS="$(docker logs "$POOL" 2>&1 || true)"
    if [[ "$POOL_LOGS" == *"IPC work unavailable"* ]] && rpc_is_active; then
        break
    fi
    sleep 1
done
[[ "${POOL_LOGS:-}" == *"IPC work unavailable"* ]] ||
    fail "pool did not observe the broken IPC session"
rpc_is_active || fail "pool did not expose RPC as active during IPC reconnect"

RECOVERY_JOBS="$(wait_for_job "$((RECOVERY_HEIGHT + 1))" "$((SECOND_JOBS + 1))" 1)" ||
    fail "IPC did not recover with a transaction-bearing job"
echo "    IPC job $RECOVERY_JOBS mines height $((RECOVERY_HEIGHT + 1)) after reconnect"

echo "==> 9/9 verify recovery happened without restarting the pool"
ipc_is_active || fail "IPC did not become active after reconnect"
[ "$(docker inspect --format '{{.State.Pid}}' "$POOL")" = "$POOL_PID" ] ||
    fail "pool process restarted instead of recovering IPC"
[[ "$(pool_cli getrawmempool)" == *"$RECOVERY_TXID"* ]] ||
    fail "recovery job did not preserve the fee transaction in Core's mempool"

echo "PASS: IPC claimed transaction fees and recovered after a live Core restart"

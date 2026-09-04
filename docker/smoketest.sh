#!/usr/bin/env bash
#
# End-to-end smoke test for the pool. Proves the whole pipeline:
#   compile + unit tests -> run the pool against a regtest bitcoind ->
#   mine with a real cpuminer -> a block the C++ pool built is accepted.
#
# Reuses the shared bitcoind + miner harness (docker/). Run from the repo root:
#   bash docker/smoketest.sh
#
set -uo pipefail

export MSYS_NO_PATHCONV=1

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })}"
COMPOSE="docker compose -f $REPO_ROOT/tools/regtest/docker-compose.yml"
CLI="$COMPOSE exec -T bitcoind bitcoin-cli -regtest -rpcuser=erikslund -rpcpassword=erikslundpass -rpcport=18443"
NET=erikslund-regtest_default
POOL=ep-smoke
MINER=ep-smoke-miner
MINER_ADDR=bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf
KEEP="${KEEP:-0}"   # KEEP=1 leaves bitcoind + pool running for debugging

PASS=0
FAIL=0
pass() { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
cleanup() {
    [ "$KEEP" = "1" ] && return 0
    docker rm -f "$MINER" >/dev/null 2>&1
    docker rm -f "$POOL" >/dev/null 2>&1
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1
}
trap cleanup EXIT

echo "==> 1/6 compile + unit tests"
docker build -q -t erikslund-pool-build "$REPO_ROOT/docker" >/dev/null
if docker run --rm -v "$REPO_ROOT:/src:ro" \
        -v erikslund-build:/build \
        erikslund-pool-build >/tmp/pool-build.log 2>&1; then
    pass "build + unit tests"
else
    fail "build / unit tests"
    tail -30 /tmp/pool-build.log
    exit 1
fi

echo "==> 2/6 start regtest bitcoind"
$COMPOSE up -d bitcoind >/dev/null 2>&1
for _ in $(seq 1 40); do $CLI getblockchaininfo >/dev/null 2>&1 && break; sleep 1; done
if START=$($CLI getblockcount 2>/dev/null); then
    pass "bitcoind ready (height $START)"
else
    fail "bitcoind not ready"
    exit 1
fi

echo "==> 3/6 start the C++ pool against bitcoind"
docker rm -f "$POOL" >/dev/null 2>&1
docker run -d --name "$POOL" --network "$NET" \
    -v erikslund-build:/build:ro \
    -v "$REPO_ROOT/docker/regtest.yml:/cfg/pool.yml:ro" \
    --entrypoint /build/cmake/erikslund-pool erikslund-pool-build --config /cfg/pool.yml >/dev/null
for _ in $(seq 1 30); do
    POOL_LOGS="$(docker logs "$POOL" 2>&1 || true)"
    [[ "$POOL_LOGS" == *"Stratum listening"* ]] && break
    sleep 1
done
# Capture-then-match, never `docker logs | grep -q`: the pipe races on
# Docker-Desktop-Windows and can false-fail even though the pool is up.
if [[ "$POOL_LOGS" == *"Stratum listening"* ]]; then
    pass "pool connected to bitcoind + listening on :3333"
else
    fail "pool did not start"
    docker logs "$POOL"
    exit 1
fi

GENERATION_BEFORE=$(docker exec "$POOL" cat /stats/work-generation)
if [ "$GENERATION_BEFORE" = "00000000000000000001" ]; then
    pass "first startup reserved work generation 1"
else
    fail "unexpected first work generation: $GENERATION_BEFORE"
fi

echo "==> 4/6 mine with a real cpuminer (up to ~45s, stops as soon as a block lands)"
$COMPOSE build miner >/dev/null 2>&1
MINER_IMG=erikslund-miner:latest
# Run the miner DETACHED and stop it with `docker rm -f` (SIGKILL). Never
# `timeout docker run --rm`: the attached CLI forwards SIGTERM to cpuminer, which
# as PID 1 ignores it, so the container never stops and `timeout` waits forever
# (this is exactly what hung CI). Poll for the block so we exit the instant it lands.
docker rm -f "$MINER" >/dev/null 2>&1
docker run -d --name "$MINER" --network "$NET" "$MINER_IMG" \
    --algo sha256d --url "stratum+tcp://$POOL:3333" \
    --user "$MINER_ADDR" --pass x --threads 2 --retry-pause 2 >/dev/null
for _ in $(seq 1 45); do
    [ "$($CLI getblockcount 2>/dev/null || echo "$START")" -gt "$START" ] && break
    sleep 1
done
docker rm -f "$MINER" >/dev/null 2>&1

echo "==> 5/6 verify a block was mined and accepted"
END=$($CLI getblockcount 2>/dev/null || echo "$START")
echo "  block height: $START -> $END"
if [ "$END" -gt "$START" ]; then
    pass "bitcoind accepted block(s) built by the C++ pool"
else
    fail "no block accepted"
fi
POOL_LOGS="$(docker logs "$POOL" 2>&1 || true)"
if [[ "$POOL_LOGS" == *"BLOCK ACCEPTED"* ]]; then
    pass "pool logged BLOCK ACCEPTED"
else
    fail "pool never logged BLOCK ACCEPTED"
fi

echo "==> 6/6 restart preserves and advances the work generation"
docker restart -t 5 "$POOL" >/dev/null
GENERATION_AFTER=""
for _ in $(seq 1 30); do
    GENERATION_AFTER=$(docker exec "$POOL" cat /stats/work-generation 2>/dev/null || true)
    if [ "$GENERATION_AFTER" = "00000000000000000002" ] &&
       docker exec "$POOL" curl -fsS http://127.0.0.1:7777/health >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if [ "$GENERATION_AFTER" = "00000000000000000002" ] &&
   docker exec "$POOL" curl -fsS http://127.0.0.1:7777/health >/dev/null 2>&1; then
    pass "pool restarted healthy with work generation 2"
else
    fail "pool did not restart with a new work generation"
    docker logs --tail 40 "$POOL"
fi

echo
if [ "$FAIL" -eq 0 ]; then
    echo "ALL CHECKS PASSED ($PASS passed)."
else
    echo "$FAIL CHECK(S) FAILED."
fi
exit "$FAIL"

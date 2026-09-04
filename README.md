# erikslund-solo-pool

A modern C++ Bitcoin solo mining pool. It builds work from Bitcoin Core, validates
shares, and submits solved blocks. Stratum V1 is the default miner protocol;
authenticated Stratum V2 Standard and Extended Channels are optional.

Solo mining means every block pays the miner's address in full, minus an optional
donation. The pool coordinates work but never divides rewards between miners.

> **Warning:** This software builds and submits real Bitcoin blocks. Test with your
> hardware on regtest or testnet before using mainnet.

## Quick start

Run against an existing node:

```sh
sudo sh deploy/setup.sh --create-directories
sudo cp conf/pool.yml /opt/erikslund-pool/etc/pool.yml

# Set the node address, RPC credentials, and ZMQ endpoint before starting.
# Use 127.0.0.1 when Bitcoin Core runs on this host.
sudoedit /opt/erikslund-pool/etc/pool.yml

docker compose -f deploy/docker-compose.yml up -d --build
```

The container runs as UID/GID 1000. Host directories must be writable by that user
so the pool can reserve mining work, persist statistics, and spool found blocks.

Graceful shutdown finishes in-flight submissions, then gives each queued live
candidate or retry one final attempt before saving statistics. Each RPC has a
timeout, but total shutdown time depends on the live backlog. Compose allows two
minutes; increase `stop_grace_period` if needed. Any remaining spooled blocks are
retried at startup.

## Configuration

[`conf/pool.yml`](conf/pool.yml) is the documented default configuration and
[`conf/pool.schema.json`](conf/pool.schema.json) defines every accepted field.

```yaml
bitcoin_nodes:
  - address: bitcoind:8332
    username: erikslund
    password: CHANGE_ME_before_deploying
stratum_listen: [0.0.0.0:3333]
api_listen: [127.0.0.1:7777]
initial_difficulty: 10000
minimum_difficulty: 1
zmq_block_endpoint: tcp://bitcoind:28332
```

| Port | Purpose |
| --- | --- |
| `3333` | Plaintext Stratum V1 |
| `3334` | Optional TLS-wrapped Stratum V1 |
| `4333` | Optional authenticated Stratum V2 |
| `7777` | Status API, health checks, and Prometheus metrics |

### Bitcoin Core IPC

IPC templates are accepted only when their parent and height match the RPC node's
tip. On mainnet, that node must also be synced and connected to peers. If RPC
permissions are restricted, allow `getblockchaininfo` and `getconnectioncount`
alongside the pool's other RPC methods. Readiness or validation failures use RPC
`getblocktemplate` fallback; IPC is retried automatically.

### Reloading configuration

After editing `pool.yml`, validate and apply runtime settings without disconnecting miners:

```sh
docker compose -f deploy/docker-compose.yml kill -s HUP pool
```

The pool parses and validates the complete file before changing anything. Difficulty/vardiff,
poll and rebroadcast intervals, fast block notification, stats intervals and retention, client and
worker caps, and idle/authentication/protocol-error limits are reloadable. A changed starting
difficulty applies to new connections; changed vardiff bounds apply to existing miners on their
next retarget.

### Stratum V1 TLS

The optional HAProxy sidecar terminates TLS on port `3334` and forwards plaintext
SV1 to the pool over loopback. Install the certificate chain and matching private
key:

```sh
sudo sh deploy/setup.sh --create-directories
sudo install -o 99 -g 99 -m 600 fullchain.pem /opt/erikslund-pool/etc/tls/server.pem
sudo install -o 99 -g 99 -m 600 privkey.pem /opt/erikslund-pool/etc/tls/server.pem.key
```

Trust the loopback sidecar in `/opt/erikslund-pool/etc/pool.yml` so PROXY v2 can
preserve miner IP addresses:

```yaml
proxy_protocol_from: [127.0.0.1]
```

Start the pool with the TLS overlay:

```sh
docker compose \
  -f deploy/docker-compose.yml \
  -f deploy/docker-compose.tls.yml \
  up -d --build
```

Point TLS-capable SV1 miners at the host on port `3334`. After renewing the
certificate, restart only the sidecar with `docker compose` and the same two
files: `restart tls`.

## Development

The toolchain image provides GCC, CMake, the dependencies, static analysis, and
sanitizers. No host compiler is required.

```sh
docker build -t erikslund-pool-build docker
docker run --rm -v "$PWD:/src:ro" -v erikslund-build:/build erikslund-pool-build
```

End-to-end tests exercise a real regtest node and native CPU miner:

```sh
bash docker/smoketest.sh
bash tools/regtest/failover-test.sh
```

The in-process submit benchmark in `tools/bench/` is built as `erikslund-bench`.

## Layout

| Path | Purpose |
| --- | --- |
| [`src/`](src/) | Pool sources, grouped by subsystem |
| [`tests/`](tests/) | Unit, adversarial, and concurrency tests |
| [`third_party/`](third_party/) | Unmodified vendored Bitcoin Core SHA-256 code |
| [`conf/`](conf/) | Pool configuration and schema |
| [`docker/`](docker/) | Reproducible build, analysis, and test tooling |
| [`deploy/`](deploy/) | Compose deployments |
| [`tools/regtest/`](tools/regtest/) | Bitcoin Core and CPU-miner regtest harness |

## License

Licensed under the [GNU General Public License v3.0 or later](LICENSE). The
vendored Bitcoin Core SHA-256 code is MIT-licensed and retains its attribution.

## Credits

- Stratum V1 design lineage from [ckpool](https://bitbucket.org/ckolivas/ckpool).

# Production image for erikslund pool. Multi-stage: GCC 16.2 on Debian
# trixie compiles the binary (libstdc++/libgcc statically linked), then a slim
# Debian runtime carries only the shared libs it needs (libcurl, libzmq).
#
# Build (from the repo root):
#   docker build -t erikslund-pool .
#
# Run with your own config (must point at a real bitcoind):
#   docker run -d --name pool -p 3333:3333 \
#     -v $PWD/my.yml:/etc/erikslund-pool/pool.yml erikslund-pool
#
# The bundled default binds the HTTP API/metrics to 127.0.0.1 (loopback only).
# To scrape /metrics from outside, set "api_listen":["0.0.0.0:7777"] in your mounted
# config and publish -p 7777:7777.

# ---- builder ---------------------------------------------------------------
FROM gcc:16.2.0-trixie AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        make \
        git \
        libcurl4-openssl-dev \
        libssl-dev \
        libzmq3-dev \
        libyaml-cpp-dev \
    && rm -rf /var/lib/apt/lists/*

# Glaze (stephenberry/glaze): the header-only JSON/YAML library used by the pool. Drop the
# include tree onto the default search path (/usr/local/include); header-only, so no link step and
# the runtime image carries nothing from it.
ARG GLAZE_VERSION=v8.3.0
RUN git clone --depth 1 --branch "${GLAZE_VERSION}" https://github.com/stephenberry/glaze.git /tmp/glaze \
    && cp -r /tmp/glaze/include/glaze /usr/local/include/glaze \
    && rm -rf /tmp/glaze

# erikslund-http-embedded: the event-driven HTTP server behind the pool's status and metrics API.
# It is installed from a pinned release like the other native dependencies. TLS, compression, and
# reflection stay off because this build does not use them.
ARG ERIKSLUND_HTTP_VERSION=0.1.2
RUN git clone --depth 1 --branch "${ERIKSLUND_HTTP_VERSION}" \
        https://github.com/eandersson/erikslund-http-embedded.git /tmp/erikslund-http-embedded \
    && cmake -S /tmp/erikslund-http-embedded -B /tmp/erikslund-http-embedded/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DERIKSLUND_HTTP_TLS=OFF \
        -DERIKSLUND_HTTP_ZLIB=OFF \
        -DERIKSLUND_HTTP_REFLECTION=OFF \
        -DERIKSLUND_HTTP_BUILD_TESTS=OFF \
        -DERIKSLUND_HTTP_BUILD_EXAMPLES=OFF \
        -DERIKSLUND_HTTP_BUILD_TOOLS=OFF \
        -DERIKSLUND_HTTP_INSTALL=ON \
        -DNATIVE_ARCH=OFF \
    && cmake --build /tmp/erikslund-http-embedded/build -j"$(nproc)" \
    && cmake --install /tmp/erikslund-http-embedded/build \
    && install -D /tmp/erikslund-http-embedded/LICENSE \
        /usr/share/doc/erikslund-http-embedded/LICENSE \
    && rm -rf /tmp/erikslund-http-embedded

# mimalloc (Microsoft): the allocator interposed for the share path's many small concurrent
# allocations. Built from a pinned release (like Glaze) instead of the distro package -- installs
# libmimalloc.so + mimalloc.h to /usr/local (MI_INSTALL_TOPLEVEL) for find_library/<mimalloc.h>.
ARG MIMALLOC_VERSION=v3.5.1
RUN git clone --depth 1 --branch "${MIMALLOC_VERSION}" https://github.com/microsoft/mimalloc.git /tmp/mimalloc \
    && cmake -S /tmp/mimalloc -B /tmp/mimalloc/build -DCMAKE_BUILD_TYPE=Release \
        -DMI_INSTALL_TOPLEVEL=ON -DMI_BUILD_TESTS=OFF \
    && cmake --build /tmp/mimalloc/build -j"$(nproc)" \
    && cmake --install /tmp/mimalloc/build \
    && rm -rf /tmp/mimalloc \
    && ldconfig

# libsecp256k1 (Bitcoin Core): BIP340 Schnorr + ElligatorSwift, the curve arithmetic behind the SV2
# Noise handshake and the authority-certificate check in src/sv2_noise. Installed here like Glaze
# and mimalloc rather than vendored into the repo. Identical stanza to docker/Dockerfile.
#
# PIC static + hidden visibility + no API visibility attributes keep the library entirely behind the
# project-owned C ABI, and only extrakeys/schnorrsig/ellswift are compiled in. Static, so the
# runtime image carries nothing from it.
ARG SECP256K1_VERSION=v0.8.0
RUN git clone --depth 1 --branch "${SECP256K1_VERSION}" \
        https://github.com/bitcoin-core/secp256k1.git /tmp/secp256k1 \
    && cmake -S /tmp/secp256k1 -B /tmp/secp256k1/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_C_VISIBILITY_PRESET=hidden \
        -DSECP256K1_INSTALL=ON \
        -DSECP256K1_ENABLE_API_VISIBILITY_ATTRIBUTES=OFF \
        -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
        -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON \
        -DSECP256K1_ENABLE_MODULE_ELLSWIFT=ON \
        -DSECP256K1_ENABLE_MODULE_ECDH=OFF \
        -DSECP256K1_ENABLE_MODULE_RECOVERY=OFF \
        -DSECP256K1_ENABLE_MODULE_MUSIG=OFF \
        -DSECP256K1_BUILD_TESTS=OFF \
        -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
        -DSECP256K1_BUILD_CTIME_TESTS=OFF \
        -DSECP256K1_BUILD_BENCHMARK=OFF \
        -DSECP256K1_BUILD_EXAMPLES=OFF \
        -DSECP256K1_VALGRIND=OFF \
    && cmake --build /tmp/secp256k1/build -j"$(nproc)" \
    && cmake --install /tmp/secp256k1/build \
    && install -D /tmp/secp256k1/COPYING /usr/share/doc/libsecp256k1/COPYING \
    && rm -rf /tmp/secp256k1 \
    && ldconfig

# ---- Cap'n Proto Mining IPC backend ------------------------------------------
# The capnp toolchain (compiler + libcapnp-dev) + the Bitcoin Core v31 mining schema graph +
# libmultiprocess mp/proxy.capnp under /opt/ipc-schema, exactly as docker/Dockerfile does, so
# CMake can `capnp compile -I/opt/ipc-schema`.
ARG BITCOIN_IPC_REF=v31.1
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends capnproto libcapnp-dev; \
    git clone --depth 1 --branch "${BITCOIN_IPC_REF}" --filter=blob:none --sparse \
        https://github.com/bitcoin/bitcoin.git /tmp/btc; \
    # proxy.capnp comes from the SAME pinned checkout (Core vendors libmultiprocess as a subtree),
    # so the whole schema graph is byte-identical to what the released bitcoind links.
    git -C /tmp/btc sparse-checkout set src/ipc/capnp src/ipc/libmultiprocess/include/mp; \
    mkdir -p /opt/ipc-schema/mp; \
    cp /tmp/btc/src/ipc/capnp/*.capnp /opt/ipc-schema/; \
    cp /tmp/btc/src/ipc/libmultiprocess/include/mp/proxy.capnp /opt/ipc-schema/mp/; \
    rm -rf /tmp/btc /var/lib/apt/lists/*

COPY CMakeLists.txt /src/
COPY src /src/src
COPY tests /src/tests
COPY third_party /src/third_party
COPY tools/bench /src/tools/bench
COPY conf /src/conf
WORKDIR /src

ARG NATIVE_ARCH=ON
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DNATIVE_ARCH=${NATIVE_ARCH} \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
    && cmake --build build --target erikslund-pool -j"$(nproc)" \
    && test -x build/erikslund-pool

RUN mkdir -p /staging/lib && cp -a /usr/local/lib/libmimalloc.so* /staging/lib/

# ---- runtime ---------------------------------------------------------------
FROM debian:trixie-slim

# libcapnp-1.1.0 (capnp / capnp-rpc / kj / kj-async) is the Cap'n Proto runtime .so the binary links.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libcurl4 libssl3t64 libzmq5 libyaml-cpp0.8 libatomic1 curl libcapnp-1.1.0 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 pool \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /var/lib/erikslund-pool \
        --shell /usr/sbin/nologin pool

COPY --from=builder /src/build/erikslund-pool /usr/local/bin/erikslund-pool
COPY --from=builder /staging/lib/ /usr/local/lib/
COPY src/sv2_noise/LICENSE-secp256k1 /usr/share/doc/erikslund-pool/LICENSE-secp256k1
COPY --from=builder /usr/share/doc/erikslund-http-embedded/LICENSE \
    /usr/share/doc/erikslund-pool/LICENSE-erikslund-http-embedded
RUN ldconfig
COPY --from=builder /src/conf/pool.yml /etc/erikslund-pool/pool.yml

# Default log dir for a standalone `docker run` with --log-file /var/log/erikslund-pool/...
# Created as root *before* dropping privileges. (The compose deploy bind-mounts a
# host dir over this path -- chown that host dir to uid 1000 so the pool can write.)
RUN mkdir -p /var/log/erikslund-pool && chown pool:pool /var/log/erikslund-pool

WORKDIR /var/lib/erikslund-pool
USER pool

EXPOSE 3333 4333 7777

HEALTHCHECK --interval=30s --timeout=4s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:7777/health || exit 1

ENTRYPOINT ["erikslund-pool"]
CMD ["--config", "/etc/erikslund-pool/pool.yml"]

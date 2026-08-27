# Toolchain image for building and testing the pool.
#
# Source is mounted read-only at /src, while the out-of-source build lives in
# a /build volume so rebuilds remain incremental.
#
# Usage (from repo root):
#   docker build -t erikslund-pool-build docker
#   docker run --rm -v "$PWD:/src:ro" \
#       -v erikslund-build:/build erikslund-pool-build
#
FROM gcc:16.2.0-trixie

ENV DEBIAN_FRONTEND=noninteractive
# The gcc image already ships g++ 16 (C++26) + make; add CMake, clang-tidy (the
# lint gate; see clang-tidy.sh), and the libraries.
RUN apt-get update && apt-get dist-upgrade -y && apt-get install -y --no-install-recommends \
        cmake \
        make \
        git \
        clang-tidy \
        cppcheck \
        libcurl4-openssl-dev \
        libssl-dev \
        libzmq3-dev \
        libyaml-cpp-dev \
        doctest-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Glaze (header-only: JSON/YAML/CBOR/... serialization + compile-time reflection): the JSON
# parser/serializer the pool builds against. Header-only -> drop the include tree onto the
# default search path (/usr/local/include); no link step.
ARG GLAZE_VERSION=v8.2.0
RUN git clone --depth 1 --branch "${GLAZE_VERSION}" https://github.com/stephenberry/glaze.git /tmp/glaze \
    && cp -r /tmp/glaze/include/glaze /usr/local/include/glaze \
    && rm -rf /tmp/glaze

# erikslund-http-embedded: the event-driven HTTP server behind the pool's status and metrics API.
# Installed from a pinned release like the other native dependencies; TLS, compression, and
# reflection are disabled because this build does not use them.
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

# mimalloc (Microsoft): the interposed allocator. Built from a pinned release (like Glaze) instead
# of the distro package -- installs libmimalloc.so + mimalloc.h to /usr/local (MI_INSTALL_TOPLEVEL).
ARG MIMALLOC_VERSION=v3.5.0
RUN git clone --depth 1 --branch "${MIMALLOC_VERSION}" https://github.com/microsoft/mimalloc.git /tmp/mimalloc \
    && cmake -S /tmp/mimalloc -B /tmp/mimalloc/build -DCMAKE_BUILD_TYPE=Release \
        -DMI_INSTALL_TOPLEVEL=ON -DMI_BUILD_TESTS=OFF \
    && cmake --build /tmp/mimalloc/build -j"$(nproc)" \
    && cmake --install /tmp/mimalloc/build \
    && rm -rf /tmp/mimalloc \
    && ldconfig

# libsecp256k1 (Bitcoin Core): BIP340 Schnorr + ElligatorSwift, the curve arithmetic behind the SV2
# Noise handshake and the authority-certificate check in src/sv2_noise. Installed here like Glaze
# and mimalloc rather than vendored into the repo.
#
# PIC static + hidden visibility + no API visibility attributes keep the library entirely behind
# sv2_noise's own C interface, and only extrakeys/schnorrsig/ellswift are compiled in.
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

# Cap'n Proto + the Bitcoin Core Mining IPC schema graph for the CapnpMiningClient backend. apt ships
# capnp/libcapnp; the Bitcoin Core schema (mining/common/init.capnp) is vendored from the pinned tag
# and libmultiprocess supplies the /mp/proxy.capnp import. All land in /opt/ipc-schema so
# `capnp compile -I/opt/ipc-schema` resolves the import graph (see CMakeLists.txt).
ARG BITCOIN_IPC_REF=v31.1
RUN apt-get update && apt-get install -y --no-install-recommends capnproto libcapnp-dev \
    && git clone --depth 1 --branch "${BITCOIN_IPC_REF}" --filter=blob:none --sparse \
        https://github.com/bitcoin/bitcoin.git /tmp/btc \
    # proxy.capnp from the SAME pinned checkout (Core vendors libmultiprocess as a subtree).
    && git -C /tmp/btc sparse-checkout set src/ipc/capnp src/ipc/libmultiprocess/include/mp \
    && mkdir -p /opt/ipc-schema/mp \
    && cp /tmp/btc/src/ipc/capnp/*.capnp /opt/ipc-schema/ \
    && cp /tmp/btc/src/ipc/libmultiprocess/include/mp/proxy.capnp /opt/ipc-schema/mp/ \
    && rm -rf /tmp/btc /var/lib/apt/lists/*

COPY build-entrypoint.sh /usr/local/bin/build-entrypoint.sh
COPY clang-tidy.sh /usr/local/bin/clang-tidy.sh
COPY cppcheck.sh /usr/local/bin/cppcheck.sh
COPY sanitize.sh /usr/local/bin/sanitize.sh
COPY tsan.sh /usr/local/bin/tsan.sh
RUN chmod +x /usr/local/bin/build-entrypoint.sh /usr/local/bin/clang-tidy.sh \
        /usr/local/bin/cppcheck.sh /usr/local/bin/sanitize.sh /usr/local/bin/tsan.sh

WORKDIR /build
ENTRYPOINT ["/usr/local/bin/build-entrypoint.sh"]

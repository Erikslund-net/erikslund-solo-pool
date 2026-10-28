cmake_minimum_required(VERSION 3.25)
project(erikslund_pool LANGUAGES C CXX)

# ---- language / warnings -----------------------------------------------------
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

add_compile_options(-Wall -Wextra -Wshadow)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---- aggressive optimization for Release (the production profile) -------------
# Release already implies -O3 -DNDEBUG; this adds LTO, loop/alignment tuning,
# dead-section GC, and full RELRO. NOTE: -march=native tunes for the BUILDING
# machine's CPU (fastest when you build on the deployment host). For a portable
# image built on a different CPU than it runs on, configure -DNATIVE_ARCH=OFF to
# avoid an illegal-instruction crash at runtime.
option(NATIVE_ARCH "Tune for the build machine's CPU (-march=native -mtune=native)" ON)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(
        -O3 -flto -fno-plt -fno-semantic-interposition
        -fno-trapping-math -fno-math-errno -funroll-loops -fomit-frame-pointer
        -falign-functions=32 -falign-loops=32 -ffunction-sections -fdata-sections -pipe)
    add_link_options(
        -flto=auto -Wl,-O3 -Wl,--as-needed -Wl,--gc-sections
        -Wl,-z,relro -Wl,-z,now)
    if(NATIVE_ARCH)
        add_compile_options(-march=native -mtune=native)
    endif()
endif()

# ---- sanitizers (opt-in; the runtime gate -- see docker/sanitize.sh) ----------
# -DSANITIZE=ON instruments a Debug build with AddressSanitizer + Undefined-
# BehaviorSanitizer for the dynamic test gate. UBSan is made fatal so a violation
# fails the run rather than only printing; frame pointers are kept for readable
# reports. Never part of Release -- the production profile stays uninstrumented.
option(SANITIZE "Instrument with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
if(SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=undefined
                        -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# -DSANITIZE_THREAD=ON instruments with ThreadSanitizer instead (TSan cannot combine with ASan,
# hence the separate option). Exercised by docker/tsan.sh against the cross-thread tests
# (reactor/work-thread write paths). Never part of Release.
option(SANITIZE_THREAD "Instrument with ThreadSanitizer" OFF)
if(SANITIZE_THREAD)
    if(SANITIZE)
        message(FATAL_ERROR "SANITIZE and SANITIZE_THREAD are mutually exclusive")
    endif()
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
    add_link_options(-fsanitize=thread)
endif()

# ---- Cap'n Proto Mining IPC backend ------------------------------------------
# CapnpMiningClient is the only Cap'n Proto-dependent application source. IpcWorkSource and the pool
# core stay protocol-free and are unit-tested with a fake.
#
# Debian's CapnProtoConfig hard-fails check_library_exists(atomic __atomic_load_8), which returns
# false on x86_64 where 8-byte atomics are compiler builtins not exported by libatomic.so -- even
# though -latomic links fine. Pre-set the cache var to skip the flawed probe (capnp still links
# atomic via CMAKE_REQUIRED_LIBRARIES).
set(FOUND_LIBATOMIC 1 CACHE INTERNAL "libatomic present (-latomic links)")
find_package(CapnProto REQUIRED)
# Generate raw Cap'n Proto C++ bindings from the vendored schema graph (docker/Dockerfile puts
# mining/common/init/echo/rpc.capnp + mp/proxy.capnp under /opt/ipc-schema). Raw `capnp compile` -- NOT
# mpgen -- so the client links only libcapnp, no Bitcoin Core interface headers. The generated
# units are third-party code; -w silences their warnings.
set(IPC_SCHEMA_DIR /opt/ipc-schema)
set(IPC_GEN_DIR ${CMAKE_BINARY_DIR}/ipc_gen)
file(MAKE_DIRECTORY ${IPC_GEN_DIR})
# The method signatures use Proxy.Context / ThreadMap types from mp/proxy.capnp, so its bindings
# (ipc_gen/mp/proxy.capnp.{h,c++}) must be generated too; the generated headers #include them.
# Init also returns Echo and Rpc interfaces the client never calls, so their bindings are needed.
set(IPC_GENERATED
    ${IPC_GEN_DIR}/mining.capnp.c++ ${IPC_GEN_DIR}/common.capnp.c++
    ${IPC_GEN_DIR}/init.capnp.c++ ${IPC_GEN_DIR}/echo.capnp.c++ ${IPC_GEN_DIR}/rpc.capnp.c++
    ${IPC_GEN_DIR}/mp/proxy.capnp.c++)
set(IPC_GENERATED_HEADERS
    ${IPC_GEN_DIR}/mining.capnp.h ${IPC_GEN_DIR}/common.capnp.h
    ${IPC_GEN_DIR}/init.capnp.h ${IPC_GEN_DIR}/echo.capnp.h ${IPC_GEN_DIR}/rpc.capnp.h
    ${IPC_GEN_DIR}/mp/proxy.capnp.h)
add_custom_command(
    OUTPUT ${IPC_GENERATED} ${IPC_GENERATED_HEADERS}
    COMMAND ${CAPNP_EXECUTABLE} compile -o${CAPNPC_CXX_EXECUTABLE}:${IPC_GEN_DIR}
            --src-prefix=${IPC_SCHEMA_DIR} -I${IPC_SCHEMA_DIR} -I/usr/include
            ${IPC_SCHEMA_DIR}/mining.capnp ${IPC_SCHEMA_DIR}/common.capnp
            ${IPC_SCHEMA_DIR}/init.capnp ${IPC_SCHEMA_DIR}/echo.capnp ${IPC_SCHEMA_DIR}/rpc.capnp
            ${IPC_SCHEMA_DIR}/mp/proxy.capnp
    DEPENDS ${IPC_SCHEMA_DIR}/mining.capnp ${IPC_SCHEMA_DIR}/common.capnp
            ${IPC_SCHEMA_DIR}/init.capnp ${IPC_SCHEMA_DIR}/echo.capnp ${IPC_SCHEMA_DIR}/rpc.capnp
            ${IPC_SCHEMA_DIR}/mp/proxy.capnp
    COMMENT "capnp: generating Mining IPC C++ bindings")
add_custom_target(generate_ipc_bindings DEPENDS ${IPC_GENERATED} ${IPC_GENERATED_HEADERS})
set_source_files_properties(${IPC_GENERATED} PROPERTIES COMPILE_OPTIONS "-w")

# ---- dependencies ------------------------------------------------------------
# Glaze (JSON/YAML) and doctest are header-only, installed on the default include path by their
# -dev packages, so they need no find_package(). libcurl + zmq need link targets.
find_package(Threads REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(erikslund-http 0.1.2 CONFIG REQUIRED)
find_library(ZMQ_LIBRARY zmq REQUIRED)
# libsecp256k1 (pinned to a release, installed to /usr/local by the Docker images like Glaze and
# mimalloc). Found here as well as inside src/sv2_noise/ so the imported target is visible in this
# directory scope -- sv2_noise::static propagates it as a link dependency, and the tests' initiator
# oracle uses it directly.
find_package(libsecp256k1 CONFIG REQUIRED)

# Build the responder tests and credential tool with the pool so `ctest` covers the native core.
set(SV2_NOISE_BUILD_CREDENTIAL_TOOL ON CACHE BOOL "" FORCE)
set(SV2_NOISE_BUILD_TESTS ON CACHE BOOL "" FORCE)
# enable_testing() must run before add_subdirectory() so the subproject's add_test() calls land in
# the generated top-level CTestTestfile.cmake.
enable_testing()
add_subdirectory(src/sv2_noise "${CMAKE_BINARY_DIR}/sv2_noise")
# yaml-cpp: config files + on-disk stats (pool.status / users/) are YAML. The
# HTTP API stays JSON. Prefer the package's CMake config; fall back to a plain
# library search if the -dev package ships no config (older distros).
find_package(yaml-cpp QUIET)
if(NOT yaml-cpp_FOUND)
    find_library(YAML_CPP_LIBRARY yaml-cpp REQUIRED)
endif()
# Optional mimalloc: a faster allocator for the many small concurrent
# allocations the share path makes. Linked into the executable with
# --no-as-needed so it interposes malloc process-wide (covering operator new).
find_library(MIMALLOC_LIBRARY mimalloc)

# ---- vendored Bitcoin Core SHA-256 (MIT, third_party/bitcoin) ----------------
# Verbatim from bitcoin/bitcoin v32.1; the fastest SHA-256 path is chosen at
# runtime. Each transform is compiled with the SIMD flags + ENABLE_* defines its
# build expects; warnings are silenced (-w) as it is upstream code we don't edit.
set(BTC_DIR ${CMAKE_SOURCE_DIR}/third_party/bitcoin)
set(BTC_CRYPTO_SOURCES ${BTC_DIR}/crypto/sha256.cpp)
set_source_files_properties(${BTC_DIR}/crypto/sha256.cpp PROPERTIES COMPILE_OPTIONS "-w")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64|i[3-6]86")
    list(APPEND BTC_CRYPTO_SOURCES
        ${BTC_DIR}/crypto/sha256_sse4.cpp ${BTC_DIR}/crypto/sha256_sse41.cpp
        ${BTC_DIR}/crypto/sha256_avx2.cpp ${BTC_DIR}/crypto/sha256_x86_shani.cpp)
    set_source_files_properties(${BTC_DIR}/crypto/sha256_sse4.cpp PROPERTIES COMPILE_OPTIONS "-w")
    set_source_files_properties(${BTC_DIR}/crypto/sha256_sse41.cpp PROPERTIES COMPILE_OPTIONS "-w;-msse4.1")
    set_source_files_properties(${BTC_DIR}/crypto/sha256_avx2.cpp PROPERTIES COMPILE_OPTIONS "-w;-mavx;-mavx2")
    set_source_files_properties(${BTC_DIR}/crypto/sha256_x86_shani.cpp PROPERTIES COMPILE_OPTIONS "-w;-msse4.1;-msha")
    set_source_files_properties(${BTC_CRYPTO_SOURCES} PROPERTIES COMPILE_DEFINITIONS "ENABLE_SSE41;ENABLE_AVX2;ENABLE_X86_SHANI")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|armv8")
    list(APPEND BTC_CRYPTO_SOURCES ${BTC_DIR}/crypto/sha256_arm_shani.cpp)
    set_source_files_properties(${BTC_DIR}/crypto/sha256_arm_shani.cpp PROPERTIES COMPILE_OPTIONS "-w;-march=armv8-a+crypto")
    set_source_files_properties(${BTC_CRYPTO_SOURCES} PROPERTIES COMPILE_DEFINITIONS "ENABLE_ARM_SHANI")
endif()

# ---- core library ------------------------------------------------------------
# Every pool .cpp under src/ except main.cpp becomes the testable core library. The Noise C core is
# a separate subproject. capnp_mining_client.cpp links only into the executable because it needs the
# generated Cap'n Proto bindings.
file(GLOB_RECURSE CORE_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/*.cpp)
list(FILTER CORE_SOURCES EXCLUDE REGEX ".*/main\\.cpp$")
list(FILTER CORE_SOURCES EXCLUDE REGEX ".*/capnp_mining_client\\.cpp$")
list(FILTER CORE_SOURCES EXCLUDE REGEX ".*/sv2_noise/.*")

add_library(erikslund_core STATIC ${CORE_SOURCES} ${BTC_CRYPTO_SOURCES})
target_include_directories(erikslund_core PUBLIC ${CMAKE_SOURCE_DIR}/src ${BTC_DIR})
target_link_libraries(
    erikslund_core
    PUBLIC Threads::Threads CURL::libcurl ${ZMQ_LIBRARY} sv2_noise::static
    PRIVATE erikslund::http)
# yaml-cpp: prefer the imported target from find_package; else the raw library.
if(yaml-cpp_FOUND)
    target_link_libraries(erikslund_core PUBLIC yaml-cpp)
else()
    target_link_libraries(erikslund_core PUBLIC ${YAML_CPP_LIBRARY})
endif()

# ---- main executable ---------------------------------------------------------
add_executable(erikslund-pool ${CMAKE_SOURCE_DIR}/src/main.cpp)
target_link_libraries(erikslund-pool PRIVATE erikslund_core)
# The Cap'n Proto Mining backend links only into the executable (keeps the core lib + tests
# capnp-free). The generated bindings live in the build dir; capnp_mining_client.cpp is our client.
target_sources(erikslund-pool PRIVATE
    ${CMAKE_SOURCE_DIR}/src/bitcoin/capnp_mining_client.cpp ${IPC_GENERATED})
target_include_directories(erikslund-pool PRIVATE ${IPC_GEN_DIR})
target_link_libraries(erikslund-pool PRIVATE
    CapnProto::capnp-rpc CapnProto::capnp CapnProto::kj-async CapnProto::kj)
# Export the dynamic symbol table so the crash handler's backtrace shows function
# names rather than bare addresses (negligible cost; just a larger symtab).
target_link_options(erikslund-pool PRIVATE -rdynamic)
if(MIMALLOC_LIBRARY)
    target_link_libraries(erikslund-pool PRIVATE
        -Wl,--no-as-needed ${MIMALLOC_LIBRARY} -Wl,--as-needed)
    target_compile_definitions(erikslund-pool PRIVATE HAVE_MIMALLOC)
    message(STATUS "mimalloc: ${MIMALLOC_LIBRARY}")
else()
    message(STATUS "mimalloc: not found -- using the system allocator")
endif()

# ---- tests -------------------------------------------------------------------
# enable_testing() is called above, before add_subdirectory(src/sv2_noise).
file(GLOB_RECURSE TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/tests/*.cpp)
add_executable(erikslund_tests ${TEST_SOURCES})
target_link_libraries(erikslund_tests PRIVATE erikslund_core)
# The production adapter exposes only the stable C ABI. Its test-only initiator oracle independently
# verifies the wire protocol with the same primitive implementations used by the official spec.
target_link_libraries(erikslund_tests PRIVATE OpenSSL::Crypto libsecp256k1::secp256k1)
# doctest's SUBCASE/CHECK macros legitimately shadow, so quiet that on tests.
target_compile_options(erikslund_tests PRIVATE -Wno-shadow)
add_test(NAME unit COMMAND erikslund_tests)

add_executable(erikslund-bench ${CMAKE_SOURCE_DIR}/tools/bench/submit_bench.cpp)
target_link_libraries(erikslund-bench PRIVATE erikslund_core)

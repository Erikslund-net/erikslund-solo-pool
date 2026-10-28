# Vendored from Bitcoin Core (MIT)

These files are copied **verbatim and unmodified** from
[bitcoin/bitcoin](https://github.com/bitcoin/bitcoin), tag **v32.1**, and are
distributed under the MIT license (see the copyright header in each file, and
Bitcoin Core's `COPYING`). MIT is compatible with this project's license.

```
crypto/sha256.h            crypto/common.h
crypto/sha256.cpp          crypto/sha256_sse4.cpp
crypto/sha256_sse41.cpp    crypto/sha256_avx2.cpp
crypto/sha256_x86_shani.cpp  crypto/sha256_arm_shani.cpp
compat/cpuid.h  compat/endian.h  compat/byteswap.h
attributes.h
```
Source tree: <https://github.com/bitcoin/bitcoin/tree/v32.1/src>

## Updating

**Do not edit these files.** To update, re-copy them from a newer Bitcoin Core
tag and re-run the tests (`tests/test_sha256.cpp` pins the vectors + genesis
hash) and the regtest smoketest (a mined block confirms byte-exact hashing).

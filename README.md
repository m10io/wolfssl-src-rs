# wolfssl-src

This crate contains the logic to build wolfSSL as a static library. It is largely based off the
[`openssl-src`] crate, and is intended to be consumed by a corresponding `*-sys` crate.

It is currently fairly incomplete, and has only been tested on Unix-based x86-64 targets.

# Build Requirements

To build wolfSSL with this crate, you will need to have a working C compiler (e.g. GCC, Clang) and
`make` installed. GNU autotools (autoconf, automake, and libtool) is also needed when building for
non-SGX targets.

# Features

A handful of optional features can be enabled by passing the appropriate `FeatureFlags` flags to the
`Build::set_features` function. Only the following `FeatureFlags` are exposed at this time:

- `HKDF`: Enable HMAC-KDF support.
- `TLS13`: Enable TLS 1.3 support.
- `CURVE25519`: Enable general Curve25519 support.
- `ED25519`: Enable Ed25519 signing support.
- `KEYGEN`: Enable RSA key generation support.
- `CERTGEN`: Enable X.509 certificate generation support.
- `AESGCM`: Enable AES GCM support.
- `PKCS7`: Enable PKCS #7/CMS support.
- `KEEP_PEER_CERT`: Keep the peer certificate in memory for a wolfSSL session for access after
  session handshake, and enable API functions related to peer certificate retrieval.

# SGX Support

SGX support is based on the [Intel SGX SDK] and is compatible with the [Rust SGX SDK].

SGX build support will be enabled automatically if the target triple ends with `-sgx`, e.g. when
using [xargo]. If a custom target is not being used, SGX support can be enabled manually using
`Builder::force_sgx`.

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

Note that this license only applies to the `wolfssl-src` crate itself and not the wolfSSL library.
For wolfSSL licensing, please refer to the [wolfSSL Licensing
Information](https://www.wolfssl.com/license/) page.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in openssl-src by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[`openssl-src`]: https://github.com/alexcrichton/openssl-src-rs
[Intel SGX SDK]: https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions/sdk.html
[Rust SGX SDK]: https://github.com/apache/incubator-teaclave-sgx-sdk
[xargo]: https://github.com/japaric/xargo

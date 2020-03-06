# wolfssl-src

This crate contains the logic to build wolfSSL as a static library. It is largely based off the
[`openssl-src`](https://github.com/alexcrichton/openssl-src-rs) crate, and is intended to be
consumed by a corresponding `*-sys` crate.

It is currently fairly incomplete, and has only been tested with `x86_64-unknown-linux-gnu` and
`x86_64-fortanix-unknown-sgx` targets.

# Build Requirements

To build wolfSSL with this crate, you will need to have a working C compiler (e.g. GCC, Clang) and
`make` installed. GNU autotools (autoconf, automake, and libtool) is also needed when building for
non-SGX targets.

For `x86_64-fortanix-unknown-sgx` targets, you should also install the Intel SGX SDK.

# Features

Curve25519 and Ed25519 support can be enabled via feature flags specified using the
`Build::set_features`. Other configuration options are not exposed at this time.

# License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in openssl-src by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

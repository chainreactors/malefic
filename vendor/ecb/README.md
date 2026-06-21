# RustCrypto: ECB

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![MIT licensed][license-image]
![Rust Version][rustc-image]
[![Build Status][build-image]][build-link]

Generic implementation of the [Electronic Codebook][ECB] (ECB) block cipher
mode of operation.

<img src="https://user-images.githubusercontent.com/7829098/171395128-0ff53e16-1969-4848-8db4-3fc4fd0cbbb4.svg" width="50%"><img src="https://user-images.githubusercontent.com/7829098/171395113-219f6995-4e2d-4f4a-bb10-d6a229c10989.svg" width="50%">

See [documentation][cipher-doc] of the `cipher` crate for additional information.

## Minimum Supported Rust Version

Rust **1.56** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License
 * [MIT license](http://opensource.org/licenses/MIT)

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/ecb.svg
[crate-link]: https://crates.io/crates/ecb
[docs-image]: https://docs.rs/ecb/badge.svg
[docs-link]: https://docs.rs/ecb/
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[build-image]: https://github.com/magic-akari/ecb/actions/workflows/test.yml/badge.svg?event=push
[build-link]: https://github.com/magic-akari/ecb/actions/workflows/test.yml

[//]: # (general links)

[ECB]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB
[cipher-doc]: https://docs.rs/cipher/

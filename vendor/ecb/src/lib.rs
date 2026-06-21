//! [Electronic Codebook][1] (ECB) mode.
//!
//! <img src="https://user-images.githubusercontent.com/7829098/171395128-0ff53e16-1969-4848-8db4-3fc4fd0cbbb4.svg" width="49%" />
//! <img src="https://user-images.githubusercontent.com/7829098/171395113-219f6995-4e2d-4f4a-bb10-d6a229c10989.svg" width="49%"/>
//!
//! Mode functionality is accessed using traits from re-exported [`cipher`] crate.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//!
//! # Example
//! ```
//! # #[cfg(feature = "block-padding")] {
//! use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};
//! use hex_literal::hex;
//!
//! type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
//! type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;
//!
//! let key = [0x42; 16];
//! let plaintext = *b"hello world! this is my plaintext.";
//! let ciphertext = hex!(
//!     "42b153410851a931eb3e6c048867ae5f"
//!     "95eb20b42e176b07840db75688be9c70"
//!     "e4670ea0d87a71be5f9f3099b4fff3dc"
//! );
//!
//! // encrypt/decrypt in-place
//! // buffer must be big enough for padded plaintext
//! let mut buf = [0u8; 48];
//! let pt_len = plaintext.len();
//! buf[..pt_len].copy_from_slice(&plaintext);
//! let ct = Aes128EcbEnc::new(&key.into())
//!     .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
//!     .unwrap();
//! assert_eq!(ct, &ciphertext[..]);
//!
//! let pt = Aes128EcbDec::new(&key.into())
//!     .decrypt_padded_mut::<Pkcs7>(&mut buf)
//!     .unwrap();
//! assert_eq!(pt, &plaintext);
//!
//! // encrypt/decrypt from buffer to buffer
//! let mut buf = [0u8; 48];
//! let ct = Aes128EcbEnc::new(&key.into())
//!     .encrypt_padded_b2b_mut::<Pkcs7>(&plaintext, &mut buf)
//!     .unwrap();
//! assert_eq!(ct, &ciphertext[..]);
//!
//! let mut buf = [0u8; 48];
//! let pt = Aes128EcbDec::new(&key.into())
//!     .decrypt_padded_b2b_mut::<Pkcs7>(&ct, &mut buf)
//!     .unwrap();
//! assert_eq!(pt, &plaintext);
//! # }
//! ```
//!
//! With enabled `alloc` (or `std`) feature you also can use allocating
//! convinience methods:
//! ```
//! # #[cfg(all(feature = "alloc", feature = "block-padding"))] {
//! # use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};
//! # use hex_literal::hex;
//! # type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
//! # type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;
//! # let key = [0x42; 16];
//! # let plaintext = *b"hello world! this is my plaintext.";
//! # let ciphertext = hex!(
//! #     "42b153410851a931eb3e6c048867ae5f"
//! #     "95eb20b42e176b07840db75688be9c70"
//! #     "e4670ea0d87a71be5f9f3099b4fff3dc"
//! # );
//! let res = Aes128EcbEnc::new(&key.into())
//!     .encrypt_padded_vec_mut::<Pkcs7>(&plaintext);
//! assert_eq!(res[..], ciphertext[..]);
//! let res = Aes128EcbDec::new(&key.into())
//!     .decrypt_padded_vec_mut::<Pkcs7>(&res)
//!     .unwrap();
//! assert_eq!(res[..], plaintext[..]);
//! # }
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_root_url = "https://docs.rs/ECB/0.1.2"
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

mod decrypt;
mod encrypt;

pub use cipher;
pub use decrypt::Decryptor;
pub use encrypt::Encryptor;

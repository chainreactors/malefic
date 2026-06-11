//! Payload decoder module
//! Feature-gated decoders delegating to malefic-codec

#[cfg(feature = "enc_xor")]
pub use malefic_codec::xor;

#[cfg(feature = "enc_uuid")]
pub use malefic_codec::uuid;

#[cfg(feature = "enc_mac")]
pub use malefic_codec::mac;

#[cfg(feature = "enc_ipv4")]
pub use malefic_codec::ipv4;

#[cfg(feature = "enc_base64")]
pub use malefic_codec::base64 as base64_dec;

#[cfg(feature = "enc_base45")]
pub use malefic_codec::base45;

#[cfg(feature = "enc_base58")]
pub use malefic_codec::base58;

#[cfg(any(feature = "enc_aes", feature = "enc_aes2"))]
pub use malefic_codec::aes as aes_dec;

#[cfg(feature = "enc_aes2")]
pub use malefic_codec::aes2;

#[cfg(feature = "enc_des")]
pub use malefic_codec::des as des_dec;

#[cfg(feature = "enc_chacha")]
pub use malefic_codec::chacha;

#[cfg(feature = "enc_rc4")]
pub use malefic_codec::rc4;

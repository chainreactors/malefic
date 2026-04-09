//! Malefic Codec - Shared payload encoding/decoding library
//!
//! Provides symmetric encode/decode for 12 payload obfuscation algorithms.
//! Used by malefic-mutant (encode side) and malefic-starship (decode side).

#[cfg(any(feature = "codec_aes", feature = "codec_aes2"))]
pub mod aes;
#[cfg(feature = "codec_aes2")]
pub mod aes2;
#[cfg(feature = "codec_base45")]
pub mod base45;
#[cfg(feature = "codec_base58")]
pub mod base58;
#[cfg(feature = "codec_base64")]
pub mod base64;
#[cfg(feature = "codec_chacha")]
pub mod chacha;
#[cfg(feature = "codec_des")]
pub mod des;
#[cfg(feature = "codec_ipv4")]
pub mod ipv4;
#[cfg(feature = "codec_mac")]
pub mod mac;
#[cfg(feature = "codec_rc4")]
pub mod rc4;
#[cfg(feature = "codec_uuid")]
pub mod uuid;
#[cfg(feature = "codec_xor")]
pub mod xor;

use malefic_gateway::ObfDebug;

/// Result of encoding a payload
#[derive(ObfDebug, Clone)]
pub struct EncodeResult {
    /// The encoded payload bytes
    pub encoded: Vec<u8>,
    /// Key material (if applicable)
    pub key: Vec<u8>,
    /// Additional key material (nonce, IV, etc.)
    pub extra: Vec<u8>,
    /// String-based output (for UUID, MAC, IPv4, base encodings)
    pub strings: Vec<String>,
}

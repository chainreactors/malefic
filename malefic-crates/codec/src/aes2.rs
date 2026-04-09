//! AES2 codec - same algorithm as AES, different output format in CLI

#[cfg(feature = "encoder")]
use crate::EncodeResult;

#[cfg(feature = "encoder")]
pub fn encode(data: &[u8]) -> EncodeResult {
    super::aes::encode(data)
}

pub fn decode(data: &[u8], key: &[u8], extra: &[u8]) -> Vec<u8> {
    super::aes::decode(data, key, extra)
}

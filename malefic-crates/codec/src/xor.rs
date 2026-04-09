//! XOR codec

#[cfg(feature = "encoder")]
use crate::EncodeResult;

#[cfg(feature = "encoder")]
pub fn encode(data: &[u8]) -> EncodeResult {
    let key = malefic_common::random::random_u8();
    let encoded: Vec<u8> = data.iter().map(|b| b ^ key).collect();
    EncodeResult {
        encoded,
        key: vec![key],
        extra: vec![],
        strings: vec![],
    }
}

pub fn decode(data: &[u8], key: &[u8], _extra: &[u8]) -> Vec<u8> {
    let k = key[0];
    data.iter().map(|b| b ^ k).collect()
}

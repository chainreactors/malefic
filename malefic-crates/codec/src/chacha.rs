//! ChaCha20 codec
//! Key: 32-byte key
//! Extra: 12-byte nonce

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

#[cfg(feature = "encoder")]
use crate::EncodeResult;

fn apply_chacha(data: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut key_arr = [0u8; 32];
    let len = key.len().min(32);
    key_arr[..len].copy_from_slice(&key[..len]);

    let mut nonce_arr = [0u8; 12];
    let nonce_len = nonce.len().min(12);
    nonce_arr[..nonce_len].copy_from_slice(&nonce[..nonce_len]);

    let mut cipher = ChaCha20::new(&key_arr.into(), &nonce_arr.into());
    let mut buf = data.to_vec();
    cipher.apply_keystream(&mut buf);
    buf
}

#[cfg(feature = "encoder")]
pub fn encode(data: &[u8]) -> EncodeResult {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    malefic_common::random::fill(&mut key);
    malefic_common::random::fill(&mut nonce);

    let encoded = apply_chacha(data, &key, &nonce);

    EncodeResult {
        encoded,
        key: key.to_vec(),
        extra: nonce.to_vec(),
        strings: vec![],
    }
}

pub fn decode(data: &[u8], key: &[u8], extra: &[u8]) -> Vec<u8> {
    apply_chacha(data, key, extra)
}

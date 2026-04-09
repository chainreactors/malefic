//! AES-256-CBC codec
//! Key derivation: SHA256(raw_key) → 32-byte AES key
//! IV: zero (matching BOAZ convention)

use aes::Aes256;
use sha2::{Digest, Sha256};

#[cfg(feature = "encoder")]
use crate::EncodeResult;

#[cfg(feature = "encoder")]
fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

fn pkcs7_unpad(data: &mut Vec<u8>, max_block: usize) {
    if let Some(&pad_len) = data.last() {
        let pad_len = pad_len as usize;
        if pad_len > 0 && pad_len <= max_block && data.len() >= pad_len {
            let valid = data[data.len() - pad_len..]
                .iter()
                .all(|&b| b == pad_len as u8);
            if valid {
                data.truncate(data.len() - pad_len);
            }
        }
    }
}

fn derive_key(raw_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(raw_key);
    hasher.finalize().into()
}

#[cfg(feature = "encoder")]
pub fn encode(data: &[u8]) -> EncodeResult {
    use cbc::{
        cipher::{BlockEncryptMut, KeyIvInit},
        Encryptor,
    };

    type Aes256CbcEnc = Encryptor<Aes256>;

    let mut raw_key = [0u8; 16];
    malefic_common::random::fill(&mut raw_key);

    let derived_key = derive_key(&raw_key);
    let iv = [0u8; 16];

    let padded = pkcs7_pad(data, 16);
    let mut buf = padded.clone();
    let cipher = Aes256CbcEnc::new(&derived_key.into(), &iv.into());
    let ct = cipher
        .encrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut buf, padded.len())
        .expect("AES encryption failed");

    EncodeResult {
        encoded: ct.to_vec(),
        key: raw_key.to_vec(),
        extra: vec![],
        strings: vec![],
    }
}

pub fn decode(data: &[u8], key: &[u8], _extra: &[u8]) -> Vec<u8> {
    use cbc::{
        cipher::{BlockDecryptMut, KeyIvInit},
        Decryptor,
    };

    type Aes256CbcDec = Decryptor<Aes256>;

    let derived_key = derive_key(key);
    let iv = [0u8; 16];

    let cipher = Aes256CbcDec::new(&derived_key.into(), &iv.into());
    let mut buf = data.to_vec();
    match cipher.decrypt_padded_mut::<aes::cipher::block_padding::NoPadding>(&mut buf) {
        Ok(pt) => {
            let mut result = pt.to_vec();
            pkcs7_unpad(&mut result, 16);
            result
        }
        Err(_) => data.to_vec(),
    }
}

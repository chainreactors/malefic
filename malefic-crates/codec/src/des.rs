//! DES-ECB codec
//! Key: 7-byte raw key (expanded to 8-byte DES key with parity bits, matching BOAZ)

use cipher::KeyInit;
use des::Des;

#[cfg(feature = "encoder")]
use crate::EncodeResult;

const BLOCK_SIZE: usize = 8;

/// Convert 7-byte key to 8-byte DES key with parity bits
fn build_des_key_7to8(raw_key: &[u8]) -> [u8; 8] {
    let mut raw7 = [0u8; 7];
    let len = raw_key.len().min(7);
    raw7[..len].copy_from_slice(&raw_key[..len]);

    let mut inbits: u64 = 0;
    for &b in &raw7 {
        inbits = (inbits << 8) | b as u64;
    }

    let mut out = [0u8; 8];
    let mut shift: i32 = 56 - 7;
    for i in 0..8 {
        let block_7 = ((inbits >> shift as u32) & 0x7F) as u8;
        shift -= 7;
        let bit_count = block_7.count_ones();
        let block_8 = (block_7 << 1) | if bit_count % 2 == 0 { 1 } else { 0 };
        out[i] = block_8;
    }
    out
}

#[cfg(feature = "encoder")]
fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

fn pkcs7_unpad(data: &mut Vec<u8>) {
    if let Some(&pad_len) = data.last() {
        let pad_len = pad_len as usize;
        if pad_len > 0 && pad_len <= BLOCK_SIZE && data.len() >= pad_len {
            let valid = data[data.len() - pad_len..]
                .iter()
                .all(|&b| b == pad_len as u8);
            if valid {
                data.truncate(data.len() - pad_len);
            }
        }
    }
}

#[cfg(feature = "encoder")]
pub fn encode(data: &[u8]) -> EncodeResult {
    use cipher::BlockEncryptMut;
    use ecb::Encryptor;

    type DesEcbEnc = Encryptor<Des>;

    let raw_key: [u8; 7] = *b"BOAZIST";
    let des_key = build_des_key_7to8(&raw_key);

    let padded = pkcs7_pad(data);
    let cipher = DesEcbEnc::new(&des_key.into());
    let mut buf = padded.clone();
    let ct = cipher
        .encrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buf, padded.len())
        .expect("DES encryption failed");

    EncodeResult {
        encoded: ct.to_vec(),
        key: raw_key.to_vec(),
        extra: vec![],
        strings: vec![],
    }
}

pub fn decode(data: &[u8], key: &[u8], _extra: &[u8]) -> Vec<u8> {
    use cipher::BlockDecryptMut;
    use ecb::Decryptor;

    type DesEcbDec = Decryptor<Des>;

    let des_key = build_des_key_7to8(key);
    let cipher = DesEcbDec::new(&des_key.into());
    let mut buf = data.to_vec();

    match cipher.decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut buf) {
        Ok(pt) => {
            let mut result = pt.to_vec();
            pkcs7_unpad(&mut result);
            result
        }
        Err(_) => data.to_vec(),
    }
}

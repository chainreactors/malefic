//! RC4 codec

#[cfg(feature = "encoder")]
use crate::EncodeResult;

fn rc4_ksa(key: &[u8]) -> [u8; 256] {
    let mut s = [0u8; 256];
    for i in 0..256 {
        s[i] = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    s
}

fn rc4_crypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut s = rc4_ksa(key);
    let mut i: u8 = 0;
    let mut j: u8 = 0;
    let mut result = Vec::with_capacity(data.len());

    for &byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        result.push(byte ^ k);
    }

    result
}

#[cfg(feature = "encoder")]
pub fn encode(data: &[u8]) -> EncodeResult {
    let mut key = [0u8; 16];
    malefic_common::random::fill(&mut key);

    let encoded = rc4_crypt(data, &key);

    EncodeResult {
        encoded,
        key: key.to_vec(),
        extra: vec![],
        strings: vec![],
    }
}

pub fn decode(data: &[u8], key: &[u8], _extra: &[u8]) -> Vec<u8> {
    rc4_crypt(data, key)
}

//! IPv4 address codec

#[cfg(feature = "encoder")]
use crate::EncodeResult;

#[cfg(feature = "encoder")]
const PAD_BYTE: u8 = 0x90;

#[cfg(feature = "encoder")]
pub fn encode(data: &[u8]) -> EncodeResult {
    let mut padded = data.to_vec();
    while padded.len() % 4 != 0 {
        padded.push(PAD_BYTE);
    }

    let mut ipv4s = Vec::new();
    for chunk in padded.chunks(4) {
        let ip = format!("{}.{}.{}.{}", chunk[0], chunk[1], chunk[2], chunk[3]);
        ipv4s.push(ip);
    }

    EncodeResult {
        encoded: padded,
        key: vec![],
        extra: vec![],
        strings: ipv4s,
    }
}

pub fn decode(data: &[u8], _key: &[u8], _extra: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(data);
    let mut result = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        for part in line.split('.') {
            if let Ok(b) = part.trim().parse::<u8>() {
                result.push(b);
            }
        }
    }

    result
}

use super::EncodeResult;
use anyhow::Result;

/// AES2 uses the same encryption as AES, but the C/Rust output includes
/// evasion wrapper code (split decryption with junk calculations).
/// The actual encoding is identical to AES.
pub fn encode(data: &[u8]) -> Result<EncodeResult> {
    let r = malefic_codec::aes2::encode(data);
    Ok(EncodeResult {
        encoded: r.encoded,
        key: r.key,
        extra: r.extra,
        strings: r.strings,
    })
}

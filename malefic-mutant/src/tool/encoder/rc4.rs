use super::EncodeResult;
use anyhow::Result;

pub fn encode(data: &[u8]) -> Result<EncodeResult> {
    let r = malefic_codec::rc4::encode(data);
    Ok(EncodeResult {
        encoded: r.encoded,
        key: r.key,
        extra: r.extra,
        strings: r.strings,
    })
}

pub(crate) static TARGET_INSTANCE_PATH: &str = "malefic-pulse/src/instance.rs";
pub(crate) static INSTANCE_TEMPLATE_PATH: &str = "malefic-pulse/src/template/instance_template";

/// Compute DJB2 hash at generation time (matches server-side hash.DJB2Hash)
pub(crate) fn djb2_hash(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for &byte in s.as_bytes() {
        hash = hash
            .wrapping_shl(5)
            .wrapping_add(hash)
            .wrapping_add(byte as u32);
    }
    hash
}

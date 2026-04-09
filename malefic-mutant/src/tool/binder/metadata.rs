/// Binder metadata structure (40 bytes, appended at file tail).

pub const BINDER_MAGIC: &[u8; 8] = b"MFCBIND\0";
pub const METADATA_SIZE: usize = 40;

/// Metadata written at the end of a bound PE file.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BinderMetadata {
    /// Magic bytes: b"MFCBIND\0"
    pub magic: [u8; 8],
    /// File offset where the secondary PE payload begins
    pub payload_offset: u64,
    /// Size of the secondary PE payload
    pub payload_size: u64,
    /// Size of the original primary PE (before binding)
    pub original_size: u64,
    /// Reserved flags
    pub flags: u32,
    /// CRC32 checksum of the payload data
    pub checksum: u32,
}

impl BinderMetadata {
    /// Serialize metadata to 40 bytes (little-endian).
    pub fn to_bytes(&self) -> [u8; METADATA_SIZE] {
        let mut buf = [0u8; METADATA_SIZE];
        buf[0..8].copy_from_slice(&self.magic);
        buf[8..16].copy_from_slice(&self.payload_offset.to_le_bytes());
        buf[16..24].copy_from_slice(&self.payload_size.to_le_bytes());
        buf[24..32].copy_from_slice(&self.original_size.to_le_bytes());
        buf[32..36].copy_from_slice(&self.flags.to_le_bytes());
        buf[36..40].copy_from_slice(&self.checksum.to_le_bytes());
        buf
    }

    /// Deserialize metadata from 40 bytes.
    pub fn from_bytes(buf: &[u8; METADATA_SIZE]) -> Option<Self> {
        let magic: [u8; 8] = buf[0..8].try_into().ok()?;
        if &magic != BINDER_MAGIC {
            return None;
        }

        Some(BinderMetadata {
            magic,
            payload_offset: u64::from_le_bytes(buf[8..16].try_into().ok()?),
            payload_size: u64::from_le_bytes(buf[16..24].try_into().ok()?),
            original_size: u64::from_le_bytes(buf[24..32].try_into().ok()?),
            flags: u32::from_le_bytes(buf[32..36].try_into().ok()?),
            checksum: u32::from_le_bytes(buf[36..40].try_into().ok()?),
        })
    }
}

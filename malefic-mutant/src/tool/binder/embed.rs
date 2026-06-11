/// Binder embed/extract/check operations using overlay appending.
use anyhow::{anyhow, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use super::metadata::{BinderMetadata, BINDER_MAGIC, METADATA_SIZE};

/// Bind a secondary PE file onto a primary PE file using overlay embedding.
///
/// Layout: [primary PE data] [secondary PE data] [BinderMetadata (40 bytes)]
pub fn bind(primary_path: &str, secondary_path: &str, output_path: &str, flags: u32) -> Result<()> {
    let primary_data = std::fs::read(primary_path)
        .map_err(|e| anyhow!("Failed to read primary file '{}': {}", primary_path, e))?;
    let secondary_data = std::fs::read(secondary_path)
        .map_err(|e| anyhow!("Failed to read secondary file '{}': {}", secondary_path, e))?;

    // Validate both are PE files (check MZ header)
    if primary_data.len() < 2 || &primary_data[0..2] != b"MZ" {
        return Err(anyhow!(
            "Primary file is not a valid PE file (missing MZ header)"
        ));
    }
    if secondary_data.len() < 2 || &secondary_data[0..2] != b"MZ" {
        return Err(anyhow!(
            "Secondary file is not a valid PE file (missing MZ header)"
        ));
    }

    let original_size = primary_data.len() as u64;
    let payload_offset = original_size;
    let payload_size = secondary_data.len() as u64;
    let checksum = crc32fast::hash(&secondary_data);

    let metadata = BinderMetadata {
        magic: *BINDER_MAGIC,
        payload_offset,
        payload_size,
        original_size,
        flags,
        checksum,
    };

    let mut output = File::create(output_path)?;
    output.write_all(&primary_data)?;
    output.write_all(&secondary_data)?;
    output.write_all(&metadata.to_bytes())?;

    Ok(())
}

/// Extract the embedded secondary PE from a bound file.
/// Returns the secondary PE data.
pub fn extract(bound_path: &str) -> Result<Vec<u8>> {
    let metadata = read_metadata(bound_path)?
        .ok_or_else(|| anyhow!("File '{}' does not contain binder metadata", bound_path))?;

    let mut file = File::open(bound_path)?;
    file.seek(SeekFrom::Start(metadata.payload_offset))?;

    let mut payload = vec![0u8; metadata.payload_size as usize];
    file.read_exact(&mut payload)?;

    // Verify CRC32
    let actual_crc = crc32fast::hash(&payload);
    if actual_crc != metadata.checksum {
        return Err(anyhow!(
            "CRC32 mismatch: expected 0x{:08X}, got 0x{:08X}",
            metadata.checksum,
            actual_crc
        ));
    }

    Ok(payload)
}

/// Check if a file contains binder metadata.
/// Returns Some(BinderMetadata) if bound, None otherwise.
pub fn check(file_path: &str) -> Result<Option<BinderMetadata>> {
    read_metadata(file_path)
}

/// Read BinderMetadata from the last 40 bytes of a file.
fn read_metadata(file_path: &str) -> Result<Option<BinderMetadata>> {
    let mut file = File::open(file_path)?;
    let file_size = file.metadata()?.len();

    if file_size < METADATA_SIZE as u64 {
        return Ok(None);
    }

    file.seek(SeekFrom::End(-(METADATA_SIZE as i64)))?;
    let mut buf = [0u8; METADATA_SIZE];
    file.read_exact(&mut buf)?;

    Ok(BinderMetadata::from_bytes(&buf))
}

/// Extract the original primary PE (without the bound payload).
#[allow(dead_code)]
pub fn extract_primary(bound_path: &str, output_path: &str) -> Result<()> {
    let metadata = read_metadata(bound_path)?
        .ok_or_else(|| anyhow!("File '{}' does not contain binder metadata", bound_path))?;

    let mut file = File::open(bound_path)?;
    let mut primary = vec![0u8; metadata.original_size as usize];
    file.read_exact(&mut primary)?;

    std::fs::write(output_path, &primary)?;
    Ok(())
}

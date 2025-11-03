use anyhow::{anyhow, Result};
use goblin::pe::PE;
use std::fs;

pub struct PEObjCopy;

impl PEObjCopy {
    /// Extract binary data from PE file (similar to objcopy -O binary)
    /// This extracts the raw executable sections from a PE file
    pub fn extract_binary(pe_path: &str, output_path: &str) -> Result<()> {
        let buffer = fs::read(pe_path)
            .map_err(|e| anyhow!("Failed to read PE file '{}': {}", pe_path, e))?;

        let pe = PE::parse(&buffer)
            .map_err(|e| anyhow!("Failed to parse PE file '{}': {}", pe_path, e))?;

        // Extract all executable sections
        let mut binary_data = Vec::new();

        for section in &pe.sections {
            // Check if section contains executable code (IMAGE_SCN_CNT_CODE = 0x20)
            if section.characteristics & 0x20 != 0 {
                if let Ok(Some(section_data)) = section.data(&buffer) {
                    binary_data.extend_from_slice(&section_data);
                }
            }
        }

        if binary_data.is_empty() {
            return Err(anyhow!("No executable sections found in PE file"));
        }

        fs::write(output_path, binary_data)
            .map_err(|e| anyhow!("Failed to write binary file '{}': {}", output_path, e))?;

        println!(
            "✅ Extracted binary data from '{}' to '{}'",
            pe_path, output_path
        );
        Ok(())
    }

    /// Extract raw file content (entire file as binary)
    #[allow(dead_code)]
    pub fn extract_raw(pe_path: &str, output_path: &str) -> Result<()> {
        let buffer =
            fs::read(pe_path).map_err(|e| anyhow!("Failed to read file '{}': {}", pe_path, e))?;

        fs::write(output_path, buffer)
            .map_err(|e| anyhow!("Failed to write binary file '{}': {}", output_path, e))?;

        println!("✅ Copied raw file from '{}' to '{}'", pe_path, output_path);
        Ok(())
    }
}

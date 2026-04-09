use crate::tool::pe::PEParser;
use crate::tool::sigforge::error::SignError;
use byteorder::{LittleEndian, WriteBytesExt};
use std::fs::{copy, File};
use std::io::{Seek, SeekFrom};
type Result<T> = std::result::Result<T, SignError>;
pub struct SignatureRemover;

impl SignatureRemover {
    /// Remove signature from a signed PE file
    pub fn remove_signature(input_path: &str, output_path: Option<&str>) -> Result<String> {
        // Parse input file
        let pe_info = PEParser::parse_file(input_path)?;

        if !pe_info.is_signed() {
            return Err(SignError::NotSigned);
        }

        // Determine output path
        let output_path = output_path
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}_nosig", input_path));

        // Copy input file to output
        copy(input_path, &output_path)?;

        // Open output file for modification
        let mut output_file = File::options().write(true).read(true).open(&output_path)?;

        // Truncate file to remove signature data
        let new_size = pe_info.cert_location as u64;
        output_file.set_len(new_size)?;

        // Clear certificate table entries in PE header
        output_file.seek(SeekFrom::Start(pe_info.cert_table_location as u64))?;
        output_file.write_u32::<LittleEndian>(0)?; // Clear certificate table offset
        output_file.write_u32::<LittleEndian>(0)?; // Clear certificate table size

        Ok(output_path)
    }
}

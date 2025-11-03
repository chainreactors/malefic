use crate::tool::pe::PEParser;
use crate::tool::sigforge::error::SignError;
use crate::tool::sigforge::extract;
use byteorder::{LittleEndian, WriteBytesExt};
use std::fs::{copy, File};
use std::io::{Seek, SeekFrom, Write};

type Result<T> = std::result::Result<T, SignError>;

pub struct SignatureInjector;

impl SignatureInjector {
    /// Copy signature from source file to target file
    pub fn copy_signature(
        source_path: &str,
        target_path: &str,
        output_path: Option<&str>,
    ) -> Result<String> {
        // Parse source file to get signature
        let source_pe = PEParser::parse_file(source_path)?;
        if !source_pe.is_signed() {
            return Err(SignError::NotSigned);
        }

        // Read signature data
        let mut source_file = File::open(source_path)?;
        let signature =
            extract::SignatureExtractor::extract_signature(&mut source_file, &source_pe)?;

        // Inject signature into target
        Self::inject_signature_data(&signature, target_path, output_path)
    }

    /// Inject signature from file into target
    pub fn inject_from_file(
        signature_path: &str,
        target_path: &str,
        output_path: Option<&str>,
    ) -> Result<String> {
        // Read signature data from file
        let signature = std::fs::read(signature_path)?;

        Self::inject_signature_data(&signature, target_path, output_path)
    }

    /// Inject signature data into target file
    pub fn inject_signature_data(
        signature: &[u8],
        target_path: &str,
        output_path: Option<&str>,
    ) -> Result<String> {
        // Parse target file
        let target_pe = PEParser::parse_file(target_path)?;

        // Determine output path
        let output_path = output_path
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}_signed", target_path));

        // Copy target file to output
        copy(target_path, &output_path)?;

        // Open output file for modification
        let mut output_file = File::options().write(true).read(true).open(&output_path)?;

        // Get original file size
        let original_size = std::fs::metadata(target_path)?.len() as u32;

        // Update certificate table in PE header
        output_file.seek(SeekFrom::Start(target_pe.cert_table_location as u64))?;
        output_file.write_u32::<LittleEndian>(original_size)?; // Certificate table offset
        output_file.write_u32::<LittleEndian>(signature.len() as u32)?; // Certificate table size

        // Append signature to end of file
        output_file.seek(SeekFrom::End(0))?;
        output_file.write_all(signature)?;

        Ok(output_path)
    }
}

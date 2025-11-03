use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::tool::pe::structures::PEInfo;
use crate::tool::pe::PEParser;
use crate::tool::sigforge::error::SignError;

type Result<T> = std::result::Result<T, SignError>;

pub struct SignatureExtractor;

impl SignatureExtractor {
    /// Extract signature from a signed PE file
    pub fn extract_from_file(file_path: &str) -> Result<Vec<u8>> {
        let pe_info = PEParser::parse_file(file_path)?;

        if !pe_info.is_signed() {
            return Err(SignError::NotSigned);
        }

        let mut file = File::open(file_path)?;
        Self::extract_signature(&mut file, &pe_info)
    }

    /// Extract signature from an open file handle
    pub fn extract_signature(file: &mut File, pe_info: &PEInfo) -> Result<Vec<u8>> {
        if !pe_info.is_signed() {
            return Err(SignError::NotSigned);
        }

        // Seek to certificate data location
        file.seek(SeekFrom::Start(pe_info.cert_location as u64))?;

        // Read certificate data
        let mut cert_data = vec![0u8; pe_info.cert_size as usize];
        file.read_exact(&mut cert_data)?;

        Ok(cert_data)
    }

    /// Save extracted signature to file
    pub fn save_signature_to_file(signature: &[u8], output_path: &str) -> Result<()> {
        use std::fs;
        fs::write(output_path, signature)?;
        Ok(())
    }

    /// Check if a file is signed (without extracting the signature)
    pub fn check_if_signed(file_path: &str) -> Result<bool> {
        let pe_info = PEParser::parse_file(file_path)?;
        Ok(pe_info.is_signed())
    }
}

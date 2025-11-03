use super::structures::PEInfo;
use crate::tool::sigforge::error::SignError;
use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use goblin::pe::PE;
use std::fs;
use std::fs::File;
use std::io::{Seek, SeekFrom};

#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub ordinal: u32,
}

pub struct PEParser;

impl PEParser {
    pub fn parse_dll_exports(dll_path: &str) -> Result<Vec<ExportInfo>> {
        let buffer = fs::read(dll_path)
            .map_err(|e| anyhow!("Failed to read DLL file '{}': {}", dll_path, e))?;

        let pe = PE::parse(&buffer)
            .map_err(|e| anyhow!("Failed to parse PE file '{}': {}", dll_path, e))?;

        let mut exports = Vec::new();

        // Get the export data from the data directories
        if let Some(_export_data) = pe.export_data {
            // Simplified approach: use sequential ordinals starting from 1

            // Parse export names
            for (i, export) in pe.exports.iter().enumerate() {
                let name = export.name.unwrap_or("").to_string();
                // For goblin, we use sequential ordinals starting from 1
                let ordinal = i as u32 + 1;

                exports.push(ExportInfo { name, ordinal });
            }

            // Handle exports by ordinal only (no name) - simplified approach
            // In goblin, we mainly work with the named exports from pe.exports
            // Additional ordinal-only exports would need more complex parsing
        } else {
            // Fallback: just use pe.exports with sequential ordinals
            for (i, export) in pe.exports.iter().enumerate() {
                let name = export.name.unwrap_or("").to_string();
                let ordinal = i as u32 + 1; // Start from 1

                exports.push(ExportInfo { name, ordinal });
            }
        }

        if exports.is_empty() {
            return Err(anyhow!("No exports found in DLL '{}'", dll_path));
        }

        Ok(exports)
    }

    #[allow(dead_code)]
    pub fn demangle_name(mangled_name: &str, ordinal: u32) -> String {
        if mangled_name.is_empty() {
            return format!("OrdinalPlaceholder{}", ordinal);
        }

        let demangled: String = mangled_name
            .replace("?", "1")
            .replace("!", "2")
            .replace("@", "3")
            .replace("$", "4")
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '6'
                }
            })
            .collect();

        if demangled == *mangled_name {
            return demangled;
        }

        // Rust expects function names to start with a letter
        format!("a{}", demangled)
    }

    pub fn parse_file(file_path: &str) -> Result<PEInfo> {
        let mut file = File::open(file_path)?;
        Self::parse_pe_info(&mut file)
    }

    pub fn parse_pe_info(file: &mut File) -> Result<PEInfo> {
        let mut pe_info = PEInfo::new();

        // Read PE header location from offset 0x3C
        file.seek(SeekFrom::Start(0x3C))?;
        pe_info.pe_header_location = file.read_u32::<LittleEndian>()?;

        // Validate PE signature
        file.seek(SeekFrom::Start(pe_info.pe_header_location as u64))?;
        let pe_signature = file.read_u32::<LittleEndian>()?;
        if pe_signature != 0x00004550 {
            // "PE\0\0"
            return Err(SignError::InvalidPe("Invalid PE signature".to_string()).into());
        }

        // Parse COFF Header
        Self::parse_coff_header(file, &mut pe_info)?;

        // Parse Optional Header
        Self::parse_optional_header(file, &mut pe_info)?;

        Ok(pe_info)
    }

    fn parse_coff_header(file: &mut File, pe_info: &mut PEInfo) -> Result<()> {
        // COFF header starts right after PE signature
        pe_info.machine_type = file.read_u16::<LittleEndian>()?;
        pe_info.number_of_sections = file.read_u16::<LittleEndian>()?;
        pe_info.time_date_stamp = file.read_u32::<LittleEndian>()?;

        // Skip PointerToSymbolTable and NumberOfSymbols
        file.seek(SeekFrom::Current(8))?;

        pe_info.size_of_optional_header = file.read_u16::<LittleEndian>()?;
        pe_info.characteristics = file.read_u16::<LittleEndian>()?;

        Ok(())
    }

    fn parse_optional_header(file: &mut File, pe_info: &mut PEInfo) -> Result<()> {
        if pe_info.size_of_optional_header == 0 {
            return Err(SignError::InvalidPe("No optional header found".to_string()).into());
        }

        // Standard fields
        pe_info.magic = file.read_u16::<LittleEndian>()?;
        pe_info.major_linker_version = file.read_u8()?;
        pe_info.minor_linker_version = file.read_u8()?;
        pe_info.size_of_code = file.read_u32::<LittleEndian>()?;
        pe_info.size_of_initialized_data = file.read_u32::<LittleEndian>()?;
        pe_info.size_of_uninitialized_data = file.read_u32::<LittleEndian>()?;
        pe_info.address_of_entry_point = file.read_u32::<LittleEndian>()?;
        pe_info.base_of_code = file.read_u32::<LittleEndian>()?;

        // BaseOfData only exists in PE32
        if pe_info.magic != 0x20B {
            pe_info.base_of_data = Some(file.read_u32::<LittleEndian>()?);
        }

        // Windows-specific fields
        if pe_info.is_pe32_plus() {
            pe_info.image_base = file.read_u64::<LittleEndian>()?;
        } else {
            pe_info.image_base = file.read_u32::<LittleEndian>()? as u64;
        }

        pe_info.section_alignment = file.read_u32::<LittleEndian>()?;
        pe_info.file_alignment = file.read_u32::<LittleEndian>()?;
        pe_info.major_os_version = file.read_u16::<LittleEndian>()?;
        pe_info.minor_os_version = file.read_u16::<LittleEndian>()?;
        pe_info.major_image_version = file.read_u16::<LittleEndian>()?;
        pe_info.minor_image_version = file.read_u16::<LittleEndian>()?;
        pe_info.major_subsystem_version = file.read_u16::<LittleEndian>()?;
        pe_info.minor_subsystem_version = file.read_u16::<LittleEndian>()?;
        pe_info.win32_version_value = file.read_u32::<LittleEndian>()?;
        pe_info.size_of_image = file.read_u32::<LittleEndian>()?;
        pe_info.size_of_headers = file.read_u32::<LittleEndian>()?;
        pe_info.checksum = file.read_u32::<LittleEndian>()?;
        pe_info.subsystem = file.read_u16::<LittleEndian>()?;
        pe_info.dll_characteristics = file.read_u16::<LittleEndian>()?;

        if pe_info.is_pe32_plus() {
            pe_info.size_of_stack_reserve = file.read_u64::<LittleEndian>()?;
            pe_info.size_of_stack_commit = file.read_u64::<LittleEndian>()?;
            pe_info.size_of_heap_reserve = file.read_u64::<LittleEndian>()?;
            pe_info.size_of_heap_commit = file.read_u64::<LittleEndian>()?;
        } else {
            pe_info.size_of_stack_reserve = file.read_u32::<LittleEndian>()? as u64;
            pe_info.size_of_stack_commit = file.read_u32::<LittleEndian>()? as u64;
            pe_info.size_of_heap_reserve = file.read_u32::<LittleEndian>()? as u64;
            pe_info.size_of_heap_commit = file.read_u32::<LittleEndian>()? as u64;
        }

        pe_info.loader_flags = file.read_u32::<LittleEndian>()?;
        pe_info.number_of_rva_and_sizes = file.read_u32::<LittleEndian>()?;

        // Parse Data Directories
        Self::parse_data_directories(file, pe_info)?;

        Ok(())
    }

    fn parse_data_directories(file: &mut File, pe_info: &mut PEInfo) -> Result<()> {
        // Export Table
        pe_info.export_table_rva = file.read_u32::<LittleEndian>()?;
        pe_info.export_table_size = file.read_u32::<LittleEndian>()?;

        // Import Table
        pe_info.import_table_rva = file.read_u32::<LittleEndian>()?;
        pe_info.import_table_size = file.read_u32::<LittleEndian>()?;

        // Skip Resource, Exception tables (16 bytes)
        file.seek(SeekFrom::Current(16))?;

        // Certificate Table (Data Directory entry 4)
        pe_info.cert_table_location = file.stream_position()? as u32;
        pe_info.cert_location = file.read_u32::<LittleEndian>()?;
        pe_info.cert_size = file.read_u32::<LittleEndian>()?;

        Ok(())
    }
}

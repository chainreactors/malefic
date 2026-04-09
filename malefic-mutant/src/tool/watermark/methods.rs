/// Watermark embedding/reading methods for PE files.
///
/// Four methods:
/// - Checksum: write watermark into PE OptionalHeader.CheckSum field
/// - DosStub: inject data into DOS stub area (between DOS header and PE header)
/// - Section: add a new PE section containing the watermark
/// - Overlay: append watermark data after the last section (simplest)
use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::tool::pe::PEParser;

/// Watermark method selection.
#[derive(Debug, Clone, Copy)]
pub enum WatermarkMethod {
    Checksum,
    DosStub,
    Section,
    Overlay,
}

impl std::str::FromStr for WatermarkMethod {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "checksum" => Ok(WatermarkMethod::Checksum),
            "dosstub" | "dos_stub" | "dos" => Ok(WatermarkMethod::DosStub),
            "section" => Ok(WatermarkMethod::Section),
            "overlay" => Ok(WatermarkMethod::Overlay),
            _ => Err(format!(
                "'{}' is not a valid watermark method. Use: checksum, dosstub, section, overlay",
                s
            )),
        }
    }
}

impl std::fmt::Display for WatermarkMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WatermarkMethod::Checksum => write!(f, "checksum"),
            WatermarkMethod::DosStub => write!(f, "dosstub"),
            WatermarkMethod::Section => write!(f, "section"),
            WatermarkMethod::Overlay => write!(f, "overlay"),
        }
    }
}

/// Write watermark into a PE file using the specified method.
pub fn write_watermark(
    input_path: &str,
    output_path: &str,
    method: WatermarkMethod,
    watermark: &[u8],
) -> Result<()> {
    std::fs::copy(input_path, output_path)?;

    match method {
        WatermarkMethod::Checksum => write_checksum(output_path, watermark),
        WatermarkMethod::DosStub => write_dosstub(output_path, watermark),
        WatermarkMethod::Section => write_section(output_path, watermark),
        WatermarkMethod::Overlay => write_overlay(output_path, watermark),
    }
}

/// Read watermark from a PE file using the specified method.
pub fn read_watermark(
    input_path: &str,
    method: WatermarkMethod,
    size_hint: Option<usize>,
) -> Result<Vec<u8>> {
    match method {
        WatermarkMethod::Checksum => read_checksum(input_path),
        WatermarkMethod::DosStub => read_dosstub(input_path, size_hint),
        WatermarkMethod::Section => read_section(input_path),
        WatermarkMethod::Overlay => read_overlay(input_path, size_hint),
    }
}

// ─── Checksum ───

fn write_checksum(output_path: &str, watermark: &[u8]) -> Result<()> {
    if watermark.len() > 4 {
        return Err(anyhow!(
            "Checksum watermark must be <= 4 bytes, got {}",
            watermark.len()
        ));
    }

    let pe_info = PEParser::parse_file(output_path)?;
    let mut file = File::options().read(true).write(true).open(output_path)?;

    // CheckSum is at optional header start + 0x40 (64 bytes into optional header)
    // optional header starts at pe_header + 4 (PE sig) + 20 (COFF header)
    let optional_header_offset = pe_info.pe_header_location as u64 + 4 + 20;
    let checksum_offset = optional_header_offset + 64; // 0x40 into optional header

    let mut value = [0u8; 4];
    let copy_len = watermark.len().min(4);
    value[..copy_len].copy_from_slice(&watermark[..copy_len]);

    file.seek(SeekFrom::Start(checksum_offset))?;
    file.write_all(&value)?;

    Ok(())
}

fn read_checksum(input_path: &str) -> Result<Vec<u8>> {
    let pe_info = PEParser::parse_file(input_path)?;
    let mut file = File::open(input_path)?;

    let optional_header_offset = pe_info.pe_header_location as u64 + 4 + 20;
    let checksum_offset = optional_header_offset + 64;

    file.seek(SeekFrom::Start(checksum_offset))?;
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)?;

    Ok(buf.to_vec())
}

// ─── DosStub ───

fn write_dosstub(output_path: &str, watermark: &[u8]) -> Result<()> {
    let pe_info = PEParser::parse_file(output_path)?;
    let mut file = File::options().read(true).write(true).open(output_path)?;

    // DOS header is 64 bytes (0x40), e_lfanew points to PE header
    let available = pe_info.pe_header_location as usize - 0x40;

    if watermark.len() > available {
        return Err(anyhow!(
            "DOS stub has only {} bytes available, watermark is {} bytes",
            available,
            watermark.len()
        ));
    }

    // Write at offset 0x40 (right after DOS header)
    file.seek(SeekFrom::Start(0x40))?;
    file.write_all(watermark)?;

    Ok(())
}

fn read_dosstub(input_path: &str, size_hint: Option<usize>) -> Result<Vec<u8>> {
    let pe_info = PEParser::parse_file(input_path)?;
    let mut file = File::open(input_path)?;

    let available = pe_info.pe_header_location as usize - 0x40;
    let read_size = size_hint.unwrap_or(available).min(available);

    file.seek(SeekFrom::Start(0x40))?;
    let mut buf = vec![0u8; read_size];
    file.read_exact(&mut buf)?;

    Ok(buf)
}

// ─── Section ───

/// Section header info parsed from PE.
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
}

fn parse_section_headers(
    file: &mut File,
    pe_header: u32,
    num_sections: u16,
    optional_header_size: u16,
) -> Result<Vec<SectionHeader>> {
    // Section table starts after optional header
    let section_table_offset = pe_header as u64 + 4 + 20 + optional_header_size as u64;
    file.seek(SeekFrom::Start(section_table_offset))?;

    let mut sections = Vec::with_capacity(num_sections as usize);
    for _ in 0..num_sections {
        let mut name = [0u8; 8];
        file.read_exact(&mut name)?;
        let virtual_size = file.read_u32::<LittleEndian>()?;
        let virtual_address = file.read_u32::<LittleEndian>()?;
        let size_of_raw_data = file.read_u32::<LittleEndian>()?;
        let pointer_to_raw_data = file.read_u32::<LittleEndian>()?;
        // Skip: PointerToRelocations(4) + PointerToLinenumbers(4) + NumberOfRelocations(2) + NumberOfLinenumbers(2) + Characteristics(4) = 16 bytes
        file.seek(SeekFrom::Current(16))?;

        sections.push(SectionHeader {
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
        });
    }

    Ok(sections)
}

fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    (value + alignment - 1) & !(alignment - 1)
}

fn write_section(output_path: &str, watermark: &[u8]) -> Result<()> {
    let pe_info = PEParser::parse_file(output_path)?;
    let mut file = File::options().read(true).write(true).open(output_path)?;

    let sections = parse_section_headers(
        &mut file,
        pe_info.pe_header_location,
        pe_info.number_of_sections,
        pe_info.size_of_optional_header,
    )?;

    let file_alignment = pe_info.file_alignment;
    let section_alignment = pe_info.section_alignment;

    // Check if there's room for a new section header (40 bytes)
    let section_table_offset =
        pe_info.pe_header_location as u64 + 4 + 20 + pe_info.size_of_optional_header as u64;
    let section_table_end = section_table_offset + (pe_info.number_of_sections as u64) * 40;
    let new_header_end = section_table_end + 40;

    // headers must fit within SizeOfHeaders
    if new_header_end > pe_info.size_of_headers as u64 {
        return Err(anyhow!(
            "No room for new section header: need {} but SizeOfHeaders is {}",
            new_header_end,
            pe_info.size_of_headers
        ));
    }

    // Calculate new section placement
    let last_section = sections
        .last()
        .ok_or_else(|| anyhow!("PE has no sections"))?;
    let new_raw_offset = align_up(
        last_section.pointer_to_raw_data + last_section.size_of_raw_data,
        file_alignment,
    );
    let new_raw_size = align_up(watermark.len() as u32, file_alignment);
    let new_virtual_address = align_up(
        last_section.virtual_address + last_section.virtual_size,
        section_alignment,
    );
    let new_virtual_size = watermark.len() as u32;

    // Write section header at section_table_end
    file.seek(SeekFrom::Start(section_table_end))?;

    // Name: ".wmark\0\0"
    let section_name: [u8; 8] = *b".wmark\0\0";
    file.write_all(&section_name)?;
    file.write_u32::<LittleEndian>(new_virtual_size)?; // VirtualSize
    file.write_u32::<LittleEndian>(new_virtual_address)?; // VirtualAddress
    file.write_u32::<LittleEndian>(new_raw_size)?; // SizeOfRawData
    file.write_u32::<LittleEndian>(new_raw_offset)?; // PointerToRawData
    file.write_u32::<LittleEndian>(0)?; // PointerToRelocations
    file.write_u32::<LittleEndian>(0)?; // PointerToLinenumbers
    file.write_u16::<LittleEndian>(0)?; // NumberOfRelocations
    file.write_u16::<LittleEndian>(0)?; // NumberOfLinenumbers
    file.write_u32::<LittleEndian>(0x40000040)?; // Characteristics: INITIALIZED_DATA | READ

    // Update NumberOfSections
    let num_sections_offset = pe_info.pe_header_location as u64 + 4 + 2; // after PE sig + Machine
    file.seek(SeekFrom::Start(num_sections_offset))?;
    file.write_u16::<LittleEndian>(pe_info.number_of_sections + 1)?;

    // Update SizeOfImage
    let new_size_of_image = align_up(new_virtual_address + new_virtual_size, section_alignment);
    let optional_header_offset = pe_info.pe_header_location as u64 + 4 + 20;
    let size_of_image_offset = optional_header_offset + 56; // 0x38 into optional header
    file.seek(SeekFrom::Start(size_of_image_offset))?;
    file.write_u32::<LittleEndian>(new_size_of_image)?;

    // Write section data at new_raw_offset
    file.seek(SeekFrom::Start(new_raw_offset as u64))?;
    file.write_all(watermark)?;

    // Pad to file alignment
    let padding = new_raw_size as usize - watermark.len();
    if padding > 0 {
        file.write_all(&vec![0u8; padding])?;
    }

    Ok(())
}

fn read_section(input_path: &str) -> Result<Vec<u8>> {
    let pe_info = PEParser::parse_file(input_path)?;
    let mut file = File::open(input_path)?;

    let sections = parse_section_headers(
        &mut file,
        pe_info.pe_header_location,
        pe_info.number_of_sections,
        pe_info.size_of_optional_header,
    )?;

    // Find .wmark section
    let wmark_section = sections
        .iter()
        .find(|s| &s.name[..6] == b".wmark")
        .ok_or_else(|| anyhow!("No .wmark section found in PE file"))?;

    file.seek(SeekFrom::Start(wmark_section.pointer_to_raw_data as u64))?;
    let mut buf = vec![0u8; wmark_section.virtual_size as usize];
    file.read_exact(&mut buf)?;

    Ok(buf)
}

// ─── Overlay ───

fn write_overlay(output_path: &str, watermark: &[u8]) -> Result<()> {
    let mut file = File::options().read(true).write(true).open(output_path)?;

    // Write marker + size + watermark data at end of file
    // Format: [WMRK (4 bytes)] [size: u32 LE] [watermark data]
    file.seek(SeekFrom::End(0))?;
    file.write_all(b"WMRK")?;
    file.write_u32::<LittleEndian>(watermark.len() as u32)?;
    file.write_all(watermark)?;

    Ok(())
}

fn read_overlay(input_path: &str, size_hint: Option<usize>) -> Result<Vec<u8>> {
    let mut file = File::open(input_path)?;
    let file_size = file.metadata()?.len();

    if let Some(hint) = size_hint {
        // Read last `hint` bytes as raw overlay
        let offset = file_size.saturating_sub(hint as u64);
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; hint];
        file.read_exact(&mut buf)?;
        return Ok(buf);
    }

    // Search for WMRK marker from end
    // Format: [WMRK (4)] [size (4)] [data (size)]
    // So metadata is at file_end - data_size - 8
    // We need to scan backwards for the marker
    if file_size < 8 {
        return Err(anyhow!("File too small to contain overlay watermark"));
    }

    // Try reading from expected positions — scan last 64KB for marker
    let scan_start = file_size.saturating_sub(65536);
    file.seek(SeekFrom::Start(scan_start))?;
    let mut scan_buf = vec![0u8; (file_size - scan_start) as usize];
    file.read_exact(&mut scan_buf)?;

    // Find last occurrence of "WMRK"
    let marker = b"WMRK";
    let mut found_pos = None;
    for i in (0..scan_buf.len().saturating_sub(7)).rev() {
        if &scan_buf[i..i + 4] == marker {
            found_pos = Some(i);
            break;
        }
    }

    let pos = found_pos.ok_or_else(|| anyhow!("No WMRK overlay marker found"))?;

    // Read size (4 bytes after marker)
    let size_bytes = &scan_buf[pos + 4..pos + 8];
    let size =
        u32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]]) as usize;

    if pos + 8 + size > scan_buf.len() {
        return Err(anyhow!("Overlay watermark size mismatch"));
    }

    Ok(scan_buf[pos + 8..pos + 8 + size].to_vec())
}

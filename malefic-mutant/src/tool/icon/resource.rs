/// PE resource directory tree parser for icon manipulation.
///
/// PE resource directory structure (three-level tree):
///   Level 1: Resource type (RT_ICON=3, RT_GROUP_ICON=14, etc.)
///   Level 2: Resource name/ID
///   Level 3: Language
///
/// Each directory entry is 8 bytes:
///   - NameOffsetOrIntegerID: u32 (high bit set = name offset, else integer ID)
///   - DataEntryOrSubdirectoryOffset: u32 (high bit set = subdirectory, else data entry)
///
/// IMAGE_RESOURCE_DIRECTORY (16 bytes):
///   - Characteristics: u32
///   - TimeDateStamp: u32
///   - MajorVersion: u16
///   - MinorVersion: u16
///   - NumberOfNamedEntries: u16
///   - NumberOfIdEntries: u16
///
/// IMAGE_RESOURCE_DATA_ENTRY (16 bytes):
///   - OffsetToData: u32 (RVA)
///   - Size: u32
///   - CodePage: u32
///   - Reserved: u32
use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Cursor, Seek, SeekFrom};

/// Resource type constants.
pub const RT_ICON: u32 = 3;
pub const RT_GROUP_ICON: u32 = 14;

/// A parsed resource data entry pointing to actual data.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResourceDataEntry {
    /// RVA of the resource data.
    pub rva: u32,
    /// Size of the resource data.
    pub size: u32,
    /// File offset of this data entry structure (for rewriting).
    pub entry_file_offset: u64,
    /// File offset of the actual data (rva converted).
    pub data_file_offset: u64,
}

/// A parsed resource entry at any level.
#[derive(Debug, Clone)]
pub struct ResourceEntry {
    /// Integer ID or name ID.
    pub id: u32,
    /// If this is a leaf: the data entry.
    pub data: Option<ResourceDataEntry>,
    /// If this is a directory: child entries.
    pub children: Vec<ResourceEntry>,
}

/// Information about the .rsrc section.
#[derive(Debug, Clone)]
pub struct RsrcSectionInfo {
    /// Virtual address of .rsrc section.
    pub virtual_address: u32,
    /// File offset of .rsrc section.
    pub file_offset: u32,
    /// Size of .rsrc section on disk.
    pub raw_size: u32,
}

impl RsrcSectionInfo {
    /// Convert an RVA within .rsrc to a file offset.
    pub fn rva_to_file_offset(&self, rva: u32) -> u64 {
        (rva - self.virtual_address + self.file_offset) as u64
    }

    /// Convert a file offset within .rsrc to an RVA.
    #[allow(dead_code)]
    pub fn file_offset_to_rva(&self, offset: u64) -> u32 {
        (offset as u32 - self.file_offset) + self.virtual_address
    }
}

/// Find the .rsrc section in a PE file using goblin.
pub fn find_rsrc_section(pe_data: &[u8]) -> Result<RsrcSectionInfo> {
    let pe = goblin::pe::PE::parse(pe_data).map_err(|e| anyhow!("Failed to parse PE: {}", e))?;

    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name);
        if name.starts_with(".rsrc") {
            return Ok(RsrcSectionInfo {
                virtual_address: section.virtual_address,
                file_offset: section.pointer_to_raw_data,
                raw_size: section.size_of_raw_data,
            });
        }
    }

    Err(anyhow!("No .rsrc section found in PE file"))
}

/// Parse the resource directory tree from .rsrc section data.
/// `rsrc_data` is the raw bytes of the .rsrc section.
/// Returns the top-level resource entries.
pub fn parse_resource_directory(
    rsrc_data: &[u8],
    rsrc_info: &RsrcSectionInfo,
) -> Result<Vec<ResourceEntry>> {
    let mut cursor = Cursor::new(rsrc_data);
    parse_directory_level(&mut cursor, 0, rsrc_data, rsrc_info)
}

fn parse_directory_level(
    cursor: &mut Cursor<&[u8]>,
    offset: u32,
    rsrc_data: &[u8],
    rsrc_info: &RsrcSectionInfo,
) -> Result<Vec<ResourceEntry>> {
    cursor.seek(SeekFrom::Start(offset as u64))?;

    // IMAGE_RESOURCE_DIRECTORY (16 bytes)
    let _characteristics = cursor.read_u32::<LittleEndian>()?;
    let _timestamp = cursor.read_u32::<LittleEndian>()?;
    let _major_version = cursor.read_u16::<LittleEndian>()?;
    let _minor_version = cursor.read_u16::<LittleEndian>()?;
    let num_named = cursor.read_u16::<LittleEndian>()?;
    let num_id = cursor.read_u16::<LittleEndian>()?;

    let total_entries = num_named as u32 + num_id as u32;
    let mut entries = Vec::with_capacity(total_entries as usize);

    for _ in 0..total_entries {
        let name_or_id = cursor.read_u32::<LittleEndian>()?;
        let data_or_subdir = cursor.read_u32::<LittleEndian>()?;

        let id = name_or_id & 0x7FFFFFFF;
        let is_subdir = (data_or_subdir & 0x80000000) != 0;

        if is_subdir {
            let subdir_offset = data_or_subdir & 0x7FFFFFFF;
            let saved_pos = cursor.position();
            let children = parse_directory_level(cursor, subdir_offset, rsrc_data, rsrc_info)?;
            cursor.seek(SeekFrom::Start(saved_pos))?;
            entries.push(ResourceEntry {
                id,
                data: None,
                children,
            });
        } else {
            // Data entry
            let data_entry_offset = data_or_subdir;
            let saved_pos = cursor.position();
            cursor.seek(SeekFrom::Start(data_entry_offset as u64))?;

            let rva = cursor.read_u32::<LittleEndian>()?;
            let size = cursor.read_u32::<LittleEndian>()?;
            let _code_page = cursor.read_u32::<LittleEndian>()?;
            let _reserved = cursor.read_u32::<LittleEndian>()?;

            let data_file_offset = rsrc_info.rva_to_file_offset(rva);
            let entry_file_offset = rsrc_info.file_offset as u64 + data_entry_offset as u64;

            cursor.seek(SeekFrom::Start(saved_pos))?;
            entries.push(ResourceEntry {
                id,
                data: Some(ResourceDataEntry {
                    rva,
                    size,
                    entry_file_offset,
                    data_file_offset,
                }),
                children: Vec::new(),
            });
        }
    }

    Ok(entries)
}

/// Find all RT_ICON data entries in the resource tree.
#[allow(dead_code)]
pub fn find_icon_entries(entries: &[ResourceEntry]) -> Vec<&ResourceDataEntry> {
    let mut result = Vec::new();
    for entry in entries {
        if entry.id == RT_ICON {
            collect_data_entries(&entry.children, &mut result);
        }
    }
    result
}

/// Find all RT_GROUP_ICON data entries in the resource tree.
pub fn find_group_icon_entries(entries: &[ResourceEntry]) -> Vec<&ResourceDataEntry> {
    let mut result = Vec::new();
    for entry in entries {
        if entry.id == RT_GROUP_ICON {
            collect_data_entries(&entry.children, &mut result);
        }
    }
    result
}

/// Recursively collect all leaf data entries.
fn collect_data_entries<'a>(entries: &'a [ResourceEntry], result: &mut Vec<&'a ResourceDataEntry>) {
    for entry in entries {
        if let Some(ref data) = entry.data {
            result.push(data);
        }
        if !entry.children.is_empty() {
            collect_data_entries(&entry.children, result);
        }
    }
}

/// Parse a GRPICONDIR from raw resource data to extract icon IDs and sizes.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GrpIconDirEntry {
    pub width: u8,
    pub height: u8,
    pub color_count: u8,
    pub planes: u16,
    pub bit_count: u16,
    pub bytes_in_res: u32,
    pub id: u16,
}

pub fn parse_grp_icon_dir(data: &[u8]) -> Result<Vec<GrpIconDirEntry>> {
    if data.len() < 6 {
        return Err(anyhow!("GRPICONDIR too small"));
    }

    let count = u16::from_le_bytes([data[4], data[5]]) as usize;
    let expected_size = 6 + count * 14;

    if data.len() < expected_size {
        return Err(anyhow!(
            "GRPICONDIR truncated: need {} bytes, got {}",
            expected_size,
            data.len()
        ));
    }

    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let off = 6 + i * 14;
        entries.push(GrpIconDirEntry {
            width: data[off],
            height: data[off + 1],
            color_count: data[off + 2],
            planes: u16::from_le_bytes([data[off + 4], data[off + 5]]),
            bit_count: u16::from_le_bytes([data[off + 6], data[off + 7]]),
            bytes_in_res: u32::from_le_bytes([
                data[off + 8],
                data[off + 9],
                data[off + 10],
                data[off + 11],
            ]),
            id: u16::from_le_bytes([data[off + 12], data[off + 13]]),
        });
    }

    Ok(entries)
}

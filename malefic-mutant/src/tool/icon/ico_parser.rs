/// ICO file format parser.
///
/// ICO file structure:
///   ICONDIR header (6 bytes):
///     - reserved: u16 (always 0)
///     - type: u16 (1 = ICO, 2 = CUR)
///     - count: u16 (number of images)
///   ICONDIRENTRY array (16 bytes each):
///     - width: u8 (0 = 256)
///     - height: u8 (0 = 256)
///     - color_count: u8
///     - reserved: u8
///     - planes: u16
///     - bit_count: u16
///     - bytes_in_res: u32 (size of image data)
///     - image_offset: u32 (offset from file start)
///   Image data follows.
use anyhow::{anyhow, Result};

/// Parsed ICO directory entry.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct IcoEntry {
    pub width: u8,
    pub height: u8,
    pub color_count: u8,
    pub reserved: u8,
    pub planes: u16,
    pub bit_count: u16,
    pub bytes_in_res: u32,
    pub image_offset: u32,
}

impl IcoEntry {
    /// Actual width (0 means 256).
    #[allow(dead_code)]
    pub fn actual_width(&self) -> u32 {
        if self.width == 0 {
            256
        } else {
            self.width as u32
        }
    }

    /// Actual height (0 means 256).
    #[allow(dead_code)]
    pub fn actual_height(&self) -> u32 {
        if self.height == 0 {
            256
        } else {
            self.height as u32
        }
    }
}

/// Parsed ICO file.
#[derive(Debug, Clone)]
pub struct IcoFile {
    pub image_type: u16,
    pub entries: Vec<IcoEntry>,
    pub image_data: Vec<Vec<u8>>,
}

/// Parse an ICO file from raw bytes.
pub fn parse_ico(data: &[u8]) -> Result<IcoFile> {
    if data.len() < 6 {
        return Err(anyhow!("ICO file too small (< 6 bytes)"));
    }

    let reserved = u16::from_le_bytes([data[0], data[1]]);
    let image_type = u16::from_le_bytes([data[2], data[3]]);
    let count = u16::from_le_bytes([data[4], data[5]]);

    if reserved != 0 {
        return Err(anyhow!("Invalid ICO header: reserved field is not 0"));
    }

    if image_type != 1 && image_type != 2 {
        return Err(anyhow!(
            "Invalid ICO type: {} (expected 1=ICO or 2=CUR)",
            image_type
        ));
    }

    let header_size = 6 + count as usize * 16;
    if data.len() < header_size {
        return Err(anyhow!(
            "ICO file truncated: need {} bytes for header, got {}",
            header_size,
            data.len()
        ));
    }

    let mut entries = Vec::with_capacity(count as usize);
    let mut image_data = Vec::with_capacity(count as usize);

    for i in 0..count as usize {
        let offset = 6 + i * 16;
        let entry = IcoEntry {
            width: data[offset],
            height: data[offset + 1],
            color_count: data[offset + 2],
            reserved: data[offset + 3],
            planes: u16::from_le_bytes([data[offset + 4], data[offset + 5]]),
            bit_count: u16::from_le_bytes([data[offset + 6], data[offset + 7]]),
            bytes_in_res: u32::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]),
            image_offset: u32::from_le_bytes([
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]),
        };

        let img_start = entry.image_offset as usize;
        let img_end = img_start + entry.bytes_in_res as usize;

        if img_end > data.len() {
            return Err(anyhow!(
                "ICO entry {} image data out of bounds: offset={}, size={}, file_len={}",
                i,
                img_start,
                entry.bytes_in_res,
                data.len()
            ));
        }

        image_data.push(data[img_start..img_end].to_vec());
        entries.push(entry);
    }

    Ok(IcoFile {
        image_type,
        entries,
        image_data,
    })
}

/// Build a GRPICONDIR structure for PE resource (RT_GROUP_ICON).
///
/// GRPICONDIR:
///   reserved: u16 (0)
///   type: u16 (1)
///   count: u16
///   GRPICONDIRENTRY array (14 bytes each):
///     - width: u8
///     - height: u8
///     - color_count: u8
///     - reserved: u8
///     - planes: u16
///     - bit_count: u16
///     - bytes_in_res: u32
///     - id: u16 (RT_ICON resource ID)
#[allow(dead_code)]
pub fn build_grp_icon_dir(ico: &IcoFile, base_id: u16) -> Vec<u8> {
    let count = ico.entries.len() as u16;
    let mut buf = Vec::with_capacity(6 + count as usize * 14);

    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.extend_from_slice(&ico.image_type.to_le_bytes()); // type
    buf.extend_from_slice(&count.to_le_bytes()); // count

    for (i, entry) in ico.entries.iter().enumerate() {
        buf.push(entry.width);
        buf.push(entry.height);
        buf.push(entry.color_count);
        buf.push(0); // reserved
        buf.extend_from_slice(&entry.planes.to_le_bytes());
        buf.extend_from_slice(&entry.bit_count.to_le_bytes());
        buf.extend_from_slice(&entry.bytes_in_res.to_le_bytes());
        buf.extend_from_slice(&(base_id + i as u16).to_le_bytes()); // nID
    }

    buf
}

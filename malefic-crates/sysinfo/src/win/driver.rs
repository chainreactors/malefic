use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use obfstr::obfstr;
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    GetDriveTypeW,
    GetLogicalDriveStringsW,
    // DRIVE_CDROM, DRIVE_FIXED, DRIVE_NO_ROOT_DIR, DRIVE_RAMDISK,
    // DRIVE_REMOTE, DRIVE_REMOVABLE, DRIVE_UNKNOWN,
};
const DRIVE_UNKNOWN: u32 = 0;
const DRIVE_NO_ROOT_DIR: u32 = 1;
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const DRIVE_REMOTE: u32 = 4;
const DRIVE_CDROM: u32 = 5;
const DRIVE_RAMDISK: u32 = 6;

pub fn enum_drivers() -> Vec<(String, String)> {
    let mut drives = Vec::new();
    let mut buffer = vec![0u16; 256];

    let len = unsafe { GetLogicalDriveStringsW(Some(&mut buffer)) as usize };

    if len == 0 {
        eprintln!("{}", obfstr!("[-] Failed to get logical drive strings."));
        return drives;
    }

    let mut i = 0;
    while i < len {
        // Extract current drive letter (null-terminated wide character string)
        let mut end = i;
        while buffer[end] != 0 {
            end += 1;
        }
        let slice = &buffer[i..end];
        let drive = OsString::from_wide(slice).to_string_lossy().to_string();

        // Get drive type
        let dtype = unsafe { GetDriveTypeW(PCWSTR(buffer.as_ptr().add(i))) };
        let dtype_str = match dtype {
            DRIVE_UNKNOWN => obfstr!("Unknown").to_string(),
            DRIVE_NO_ROOT_DIR => obfstr!("Invalid root path").to_string(),
            DRIVE_REMOVABLE => obfstr!("Removable drive").to_string(),
            DRIVE_FIXED => obfstr!("Fixed drive").to_string(),
            DRIVE_REMOTE => obfstr!("Network drive").to_string(),
            DRIVE_CDROM => obfstr!("CD-ROM drive").to_string(),
            DRIVE_RAMDISK => obfstr!("RAM disk").to_string(),
            _ => obfstr!("Other").to_string(),
        };

        drives.push((drive, dtype_str));

        // Skip to next string
        i = end + 1;
    }

    drives
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_drivers() {
        let drives = enum_drivers();
        // Check returned drive name format
        for (drive, drive_type) in &drives {
            let valid_types = [
                obfstr!("Unknown"),
                obfstr!("Invalid root path"),
                obfstr!("Removable drive"),
                obfstr!("Fixed drive"),
                obfstr!("Network drive"),
                obfstr!("CD-ROM drive"),
                obfstr!("RAM disk"),
                obfstr!("Other"),
            ];
        }
        println!("{}", obfstr!("Found drives:"));
        for (drive, drive_type) in &drives {
            println!("  {} -> {}", drive, drive_type);
        }
    }

    #[test]
    fn test_drive_constants() {
        assert_eq!(DRIVE_UNKNOWN, 0);
        assert_eq!(DRIVE_NO_ROOT_DIR, 1);
        assert_eq!(DRIVE_REMOVABLE, 2);
        assert_eq!(DRIVE_FIXED, 3);
        assert_eq!(DRIVE_REMOTE, 4);
        assert_eq!(DRIVE_CDROM, 5);
        assert_eq!(DRIVE_RAMDISK, 6);
    }
}

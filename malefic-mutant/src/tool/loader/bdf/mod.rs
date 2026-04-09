//! Binary backdoor factory - PE code cave injection and section addition

pub mod evasion;
pub mod pe;
pub mod resolver;

/// Describes a contiguous block of null bytes inside a PE section.
#[derive(Debug, Clone)]
pub struct CodeCave {
    pub section_name: String,
    pub section_index: usize,
    pub start: u64,
    pub end: u64,
    pub virtual_address: u64,
    pub size: usize,
}

/// Scan raw section data for runs of null bytes that meet `min_size`.
pub fn find_caves(data: &[u8], min_size: usize) -> Vec<CodeCave> {
    let mut caves = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] == 0 {
            let start = i;
            while i < data.len() && data[i] == 0 {
                i += 1;
            }
            let size = i - start;
            if size >= min_size {
                caves.push(CodeCave {
                    section_name: String::new(),
                    section_index: 0,
                    start: start as u64,
                    end: i as u64,
                    virtual_address: 0,
                    size,
                });
            }
        } else {
            i += 1;
        }
    }
    caves
}

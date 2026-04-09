#![allow(non_snake_case)]

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::ptr::{null_mut, NonNull};

use crate::sleep::types::HEAP_GROWABLE;
use crate::sleep::winapis::{RtlAllocateHeap, RtlCreateHeap, RtlFreeHeap};

/// Global handle to the private heap used by `HypnusHeap`.
static mut HEAP_HANDLE: Option<NonNull<c_void>> = None;

/// A custom global allocator backed by a private Windows heap (RtlCreateHeap).
///
/// When used as `#[global_allocator]`, all Rust allocations flow through
/// a dedicated heap. This allows `obfuscate_heap` to XOR-encrypt every
/// live allocation during sleep and reverse the process on wake.
pub struct HypnusHeap;

impl HypnusHeap {
    /// Creates a new private heap via RtlCreateHeap, stores the handle globally.
    fn create_heap() -> *mut c_void {
        let handle = RtlCreateHeap(HEAP_GROWABLE, null_mut(), 0, 0, null_mut(), null_mut());

        if !handle.is_null() {
            unsafe { HEAP_HANDLE = Some(NonNull::new_unchecked(handle)) };
        }

        handle
    }

    /// Returns the handle to the private heap, creating it on first call.
    pub fn get() -> *mut c_void {
        unsafe {
            HEAP_HANDLE
                .map(|p| p.as_ptr())
                .unwrap_or_else(Self::create_heap)
        }
    }
}

unsafe impl GlobalAlloc for HypnusHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = Self::get();
        let size = layout.size();
        if size == 0 {
            return null_mut();
        }
        RtlAllocateHeap(heap, 0, size) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        // Zero memory before freeing (defense in depth)
        core::ptr::write_bytes(ptr, 0, layout.size());
        RtlFreeHeap(Self::get(), 0, ptr.cast());
    }
}

unsafe impl Sync for HypnusHeap {}
unsafe impl Send for HypnusHeap {}

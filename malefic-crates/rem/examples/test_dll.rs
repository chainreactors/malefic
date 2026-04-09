//! Test TinyGo DLL dispatcher — pure Rust, no bridge lib needed.
//! All bridge_* functions use simple C types (int32/void/pointer).
//!
//! cargo run --example test_dll --no-default-features --features rem_dynamic
//! Requires: librem_tinygo.dll next to exe or in PATH

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

extern "system" {
    fn LoadLibraryA(name: *const c_char) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
}

fn get(dll: *mut c_void, name: &str) -> *mut c_void {
    let c = CString::new(name).unwrap();
    let p = unsafe { GetProcAddress(dll, c.as_ptr()) };
    assert!(!p.is_null(), "GetProcAddress({}) failed", name);
    p
}

fn main() {
    println!("=== TinyGo DLL dispatcher test (Rust) ===\n");
    let mut passed = 0;
    let total = 11;

    unsafe {
        let dll_name = CString::new("librem_tinygo.dll").unwrap();
        let dll = LoadLibraryA(dll_name.as_ptr());
        assert!(!dll.is_null(), "LoadLibraryA failed");

        // All bridge_ functions use simple types — ABI-safe across MSVC/MinGW
        type IntFn = unsafe extern "C" fn() -> c_int;
        type VoidFn = unsafe extern "C" fn();
        type DialFn = unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> c_int;
        type MemRFn = unsafe extern "C" fn(c_int, *mut c_void, c_int, *mut c_int) -> c_int;
        type MemWFn = unsafe extern "C" fn(c_int, *const c_void, c_int, *mut c_int) -> c_int;
        type CloseFn = unsafe extern "C" fn(c_int) -> c_int;
        type FreeFn = unsafe extern "C" fn(*mut c_void);

        let rem_init: IntFn = std::mem::transmute(get(dll, "RemInit"));
        let init_dialer: IntFn = std::mem::transmute(get(dll, "bridge_init_dialer"));
        let rem_dial: DialFn = std::mem::transmute(get(dll, "bridge_rem_dial"));
        let mem_read: MemRFn = std::mem::transmute(get(dll, "bridge_memory_read"));
        let mem_write: MemWFn = std::mem::transmute(get(dll, "bridge_memory_write"));
        let mem_close: CloseFn = std::mem::transmute(get(dll, "bridge_memory_close"));
        let cleanup: VoidFn = std::mem::transmute(get(dll, "bridge_cleanup"));
        let free_str: FreeFn = std::mem::transmute(get(dll, "bridge_free_cstring"));

        macro_rules! test {
            ($n:expr, $name:expr, $ok:expr) => {{
                print!("  [{}] {:40} ", $n, $name);
                if $ok {
                    println!("PASS");
                    passed += 1;
                } else {
                    println!("FAIL");
                }
            }};
        }

        test!(1, "RemInit()", rem_init() == 0);
        test!(2, "RemInit() idempotent", rem_init() == 0);
        test!(3, "bridge_init_dialer()", init_dialer() == 0);
        test!(
            4,
            "bridge_init_dialer() x100",
            (0..100).all(|_| init_dialer() == 0)
        );

        // RemDial empty → error
        {
            let cmd = CString::new("").unwrap();
            let mut ptr: *mut c_char = std::ptr::null_mut();
            let err = rem_dial(cmd.as_ptr(), &mut ptr);
            test!(5, "bridge_rem_dial(\"\") error", err != 0);
            if !ptr.is_null() {
                free_str(ptr as _);
            }
        }

        // RemDial bad URL → error
        {
            let cmd = CString::new("-c invalid://x").unwrap();
            let mut ptr: *mut c_char = std::ptr::null_mut();
            let err = rem_dial(cmd.as_ptr(), &mut ptr);
            test!(6, "bridge_rem_dial(bad) error", err != 0);
            if !ptr.is_null() {
                free_str(ptr as _);
            }
        }

        // MemoryRead invalid
        {
            let mut buf = [0u8; 64];
            let mut n: c_int = 0;
            let err = mem_read(99999, buf.as_mut_ptr() as _, 64, &mut n);
            test!(7, "bridge_memory_read(invalid) error", err != 0);
        }

        // MemoryWrite invalid
        {
            let data = b"hello";
            let mut n: c_int = 0;
            let err = mem_write(99999, data.as_ptr() as _, 5, &mut n);
            test!(8, "bridge_memory_write(invalid) error", err != 0);
        }

        // MemoryClose invalid
        test!(
            9,
            "bridge_memory_close(invalid) error",
            mem_close(99999) != 0
        );

        // FreeCString NULL
        free_str(std::ptr::null_mut());
        test!(10, "bridge_free_cstring(NULL) safe", true);

        // Cleanup
        cleanup();
        test!(11, "bridge_cleanup() safe", true);
    }

    println!("\n=== Results: {}/{} passed ===", passed, total);
    std::process::exit(if passed == total { 0 } else { 1 });
}

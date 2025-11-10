#[cfg(test)]
mod hook_test {
    use detour::RawDetour;
    use std::{ffi::c_void, ptr};
    use std::ffi::CString;
    use winapi::um::{
        libloaderapi::GetModuleHandleA, 
        libloaderapi::GetProcAddress, 
        winuser::MessageBoxA,
        winnt::LPCSTR,
    };

    type FuncFn = unsafe extern "system" fn(
        hwnd: *mut c_void,
        text: LPCSTR,
        caption: LPCSTR,
        utype: u32,
    ) -> i32;


    static mut DETOUR: Option<RawDetour> = None;
    static mut ORIGINAL: Option<FuncFn> = None;

    unsafe extern "system" fn replace_func(
        hwnd: *mut c_void,
        _text: LPCSTR,
        _caption: LPCSTR,
        utype: u32,
    ) -> i32 {
        // use std::ffi::CStr;

        // 新的消息文本
        let new_text = b"Hooked by retour-rs!\0";
        let new_caption = b"Intercepted!\0";

        // 调用原始函数
        let original = ORIGINAL.expect("Original function not set!");
        original(hwnd, new_text.as_ptr() as _, new_caption.as_ptr() as _, utype)
    }
    unsafe fn install_hook() {
        // 获取 user32.dll 基址
        let u32 = CString::new("user32.dll").unwrap();
        let module_handle = GetModuleHandleA(u32.as_ptr());
        assert!(!module_handle.is_null(), "Failed to load user32.dll");

        // 获取 MessageBoxA 的地址
        let target = GetProcAddress(module_handle, b"MessageBoxA\0".as_ptr() as _);
        assert!(!target.is_null(), "Failed to find MessageBoxA");

        println!("[*] MessageBoxA address = 0x{:X}", target as usize);

        // 创建 detour
        let detour = RawDetour::new(target as *const (), replace_func as *const ())
            .expect("RawDetour failed to create");
        let trampoline = detour.trampoline();

        // 保存原始函数
        ORIGINAL = Some(std::mem::transmute(trampoline as *const ()));

        detour.enable().expect("Enable detour failed");
        DETOUR = Some(detour);

        println!("[+] Hook installed!");
    }

    unsafe fn uninstall_hook() {
        if let Some(detour) = DETOUR.take() {
            detour.disable().ok();
            println!("[-] Hook removed!");
        }
    }
    #[test]
    fn test_hook() {
        unsafe {
            install_hook();
            MessageBoxA(
                ptr::null_mut(),
                b"Hello from Rust!\0".as_ptr() as _,
                b"Original Title\0".as_ptr() as _,
                0,
            );
            uninstall_hook();
            MessageBoxA(
                ptr::null_mut(),
                b"Hello from Rust!\0".as_ptr() as _,
                b"Original Title\0".as_ptr() as _,
                0,
            );
        }
    }
}



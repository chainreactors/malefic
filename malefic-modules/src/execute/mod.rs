pub mod exec;
pub mod execute_shellcode;

#[cfg(target_os = "windows")]
#[cfg(feature = "execute_assembly")]
pub mod execute_assembly;
#[cfg(target_os = "windows")]
#[cfg(feature = "execute_bof")]
pub mod execute_bof;
#[cfg(target_os = "windows")]
#[cfg(feature = "execute_powershell")]
pub mod execute_powershell;
#[cfg(target_os = "windows")]
#[cfg(feature = "execute_armory")]
pub mod execute_armory;
#[cfg(target_os = "windows")]
#[cfg(feature = "execute_exe")]
pub mod execute_exe;
#[cfg(target_os = "windows")]
#[cfg(feature = "execute_dll")]
pub mod execute_dll;

#[cfg(target_os = "windows")]
#[cfg(feature = "execute_local")]
pub mod execute_local;

#[cfg(target_os = "windows")]
#[cfg(feature = "dllspawn")]
pub mod dllspawn;

#[cfg(target_os = "windows")]
#[cfg(feature = "inline_local")]
pub mod inline_local;
pub(crate) mod open;

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(PartialEq, Eq)]
#[repr(u32)]
pub enum Arch {
    I686 = 0,
    X86_64 = 1,
    Arm = 2,
    Aarch64 = 3,
    Mips = 4,
    Powerpc = 5,
    Powerpc64 = 6,
    Riscv32 = 7,
    Riscv64 = 8,
}

impl Arch {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Arch::I686),
            1 => Some(Arch::X86_64),
            2 => Some(Arch::Arm),
            3 => Some(Arch::Aarch64),
            4 => Some(Arch::Mips),
            5 => Some(Arch::Powerpc),
            6 => Some(Arch::Powerpc64),
            7 => Some(Arch::Riscv32),
            8 => Some(Arch::Riscv64),
            _ => None,
        }
    }
}

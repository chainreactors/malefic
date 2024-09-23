pub mod exec;
pub mod execute_shellcode;

#[cfg(target_os = "windows")]
pub mod execute_assemble;
#[cfg(target_os = "windows")]
pub mod execute_bof;
#[cfg(target_os = "windows")]
pub mod execute_powershell;
#[cfg(target_os = "windows")]
pub mod execute_armory;
#[cfg(target_os = "windows")]
pub mod execute_exe;
#[cfg(target_os = "windows")]
pub mod execute_dll;

#[cfg(target_os = "windows")]
pub mod execute_local;
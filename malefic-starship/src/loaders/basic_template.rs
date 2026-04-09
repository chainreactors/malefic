//! Loader Template 14 - Basic template (placeholder)

use crate::loaders::common::Shellcode;

#[cfg_attr(feature = "obf_junk", malefic_gateway::junk)]
pub unsafe fn execute(_shellcode: &Shellcode) -> Result<(), String> {
    debug_println!("[*] Starting loader_14: Basic template");
    debug_println!("Good morning!");
    Ok(())
}

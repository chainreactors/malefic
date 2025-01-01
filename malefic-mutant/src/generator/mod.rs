use crate::{GenerateArch, Platform, Pulse, Version};

/*
    Attention: Just for windows x86_64 and x86 arch :)
*/
pub mod win;


pub fn pulse_generate(
    config: Pulse,
    platform: Platform,
    arch: GenerateArch,
    version: Version,
    source: bool,
) -> anyhow::Result<()> {
    match platform {
        Platform::Win => {
            win::pulse::pulse_generate(config, arch, version, source)
        }
        _ => {
            anyhow::bail!("Unsupported platform.");
        }
    }
}

pub fn link_srdi_generator(
    src_path: &str,
    platform: Platform,
    arch: GenerateArch,
    target_path: &str,
    function_name: &String,
    user_data: &[u8]
) -> anyhow::Result<()> {
    match platform {
        Platform::Win => {
            win::srdi::link_srdi_generator(src_path, arch, target_path, function_name, user_data)
        }
        _ => {
            anyhow::bail!("Unsupported platform.");
        }
    }
}

pub fn malefic_srdi_generator(
    src_path: &str,
    platform: Platform,
    arch: GenerateArch,
    target_path: &str,
    function_name: &String,
    user_data: &[u8]
) -> anyhow::Result<()> {
    match platform {
        Platform::Win => {
            win::srdi::malefic_srdi_generator(src_path, &arch, target_path, function_name, user_data)
        }
        _ => {
            anyhow::bail!("Unsupported platform.");
        }
    }
}
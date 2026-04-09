use crate::config::{GenerateArch, PulseConfig, Version};
use crate::{tool, Platform};

pub mod payload;
pub mod pulse;

pub fn pulse_generate(
    config: PulseConfig,
    platform: Platform,
    arch: GenerateArch,
    version: Version,
    source: bool,
) -> anyhow::Result<()> {
    match platform {
        Platform::Win => pulse::pulse_generate(config, arch, version, source),
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
    user_data: &[u8],
) -> anyhow::Result<()> {
    match platform {
        Platform::Win => {
            tool::srdi::link_srdi_generator(src_path, arch, target_path, function_name, user_data)
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
    user_data: &[u8],
) -> anyhow::Result<()> {
    match platform {
        Platform::Win => tool::srdi::malefic_srdi_generator(
            src_path,
            &arch,
            target_path,
            function_name,
            user_data,
        ),
        _ => {
            anyhow::bail!("Unsupported platform.");
        }
    }
}

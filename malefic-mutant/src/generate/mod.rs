#[allow(unused_imports)]
use crate::{log_debug, log_info, log_step, log_success, log_warning};
use codegen::update_core_config;
use prelude::parse_yaml;
use resources::update_resources;

pub mod cargo_features;
mod codegen;
mod features;
mod prelude;
mod resources;
mod spites;

use crate::config::{Implant, Version};
use crate::generate::prelude::update_prelude_spites;
pub use cargo_features::{update_3rd_toml, update_module_toml};

fn common_config(implant: &mut Implant, version: &Version, source: bool) {
    log_step!("Updating version, build-type, and runtime...");
    cargo_features::update_features_toml(version, source, &implant.implants.runtime);
    if source {
        cargo_features::update_winkit_toml(&implant.implants, version);
    }
}

pub fn pulse(source: bool) -> anyhow::Result<()> {
    log_step!("Updating pulse configuration...");
    cargo_features::update_pulse_toml(source);
    log_success!("Pulse configuration has been updated successfully");
    Ok(())
}

fn update_config(
    r#mod: &str,
    implant: &mut Implant,
    version: &Version,
    source: bool,
    metadata_wordlist: Option<&str>,
) -> anyhow::Result<()> {
    implant.implants.r#mod = r#mod.to_string();

    let build_config = implant
        .build
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("build configuration is required but not found"))?;

    // Generate malefic-crates/config/src/lib.rs (Rust source code)
    update_core_config(&implant.basic, &implant.implants, Some(build_config))?;

    // Update resource metadata (RC/manifest)
    let metadata = build_config
        .metadata
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("metadata configuration is required but not found"))?;
    update_resources(metadata, metadata_wordlist);

    // Schema-driven feature resolution -> write to entry & proto Cargo.toml
    features::update_features(implant, version, source)?;

    // Update module feature list (dynamic module selection)
    update_module_toml(&implant.implants.modules, source);

    Ok(())
}

pub fn beacon(
    implant: &mut Implant,
    version: &Version,
    source: bool,
    metadata_wordlist: Option<&str>,
) -> anyhow::Result<()> {
    log_step!("Updating beacon configuration...");
    common_config(implant, version, source);
    spites::update_malefic_spites(&implant.implants, &implant.basic.key, source)?;
    update_config("beacon", implant, version, source, metadata_wordlist)?;
    log_success!("Beacon configuration has been updated successfully");
    Ok(())
}

pub fn bind(
    implant: &mut Implant,
    version: &Version,
    source: bool,
    metadata_wordlist: Option<&str>,
) -> anyhow::Result<()> {
    log_step!("Updating bind configuration...");
    common_config(implant, version, source);
    update_config("bind", implant, version, source, metadata_wordlist)?;
    log_success!("Bind configuration has been updated successfully");
    Ok(())
}

pub fn prelude(
    implant: &mut Implant,
    version: &Version,
    source: bool,
    prelude_yaml_path: &str,
    resources: &str,
    key: &str,
    spite: &str,
    metadata_wordlist: Option<&str>,
) -> anyhow::Result<()> {
    log_step!("Updating prelude configuration...");
    common_config(implant, version, source);
    let autorun_yaml = std::fs::read_to_string(prelude_yaml_path)?;
    let parsed = parse_yaml(&autorun_yaml);
    if !parsed.regular_modules.is_empty() {
        cargo_features::update_module_toml(&parsed.regular_modules, source);
    }
    if !parsed.third_modules.is_empty() {
        cargo_features::update_3rd_toml(&parsed.third_modules);
    }
    update_prelude_spites(parsed, resources, key, spite)?;

    let build_config = implant
        .build
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("build configuration is required"))?;
    let metadata = build_config
        .metadata
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("metadata configuration is required but not found"))?;
    update_resources(metadata, metadata_wordlist);

    // Schema-driven feature resolution for prelude too
    features::update_features(implant, version, source)?;

    Ok(())
}

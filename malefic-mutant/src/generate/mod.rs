#[allow(unused_imports)]
use crate::{log_step, log_success};
use crate::{Implant, Version};
use config_core::{update_core_config, update_core_toml};
use config_helper::update_helper_toml;
use config_malefic::update_beacon_toml;
use config_metadata::update_resources;
use config_prelude::parse_yaml;
use config_proto::update_proto_toml;

mod config_3rd;
mod config_core;
mod config_helper;
mod config_malefic;
mod config_metadata;
mod config_modules;
mod config_prelude;
mod config_proto;
mod config_pulse;
mod config_toml;
mod config_winkit;
mod config_workspace;

use crate::generate::config_malefic::update_malefic_spites;
use crate::generate::config_prelude::update_prelude_spites;
pub use config_3rd::*;
pub use config_core::*;
pub use config_modules::*;
pub use config_pulse::*;
pub use config_toml::*;
pub use config_workspace::*;

pub fn update_pulse_config(source: bool) -> anyhow::Result<()> {
    log_step!("Updating pulse configuration...");
    config_pulse::update_pulse_toml(source);
    log_success!("Pulse configuration has been updated successfully");
    Ok(())
}

pub fn update_common_config(_implant: &mut Implant, version: &Version, source: bool) {
    log_step!("Updating version and build-type...");
    update_helper_toml(version, source);
    if source {
        use config_winkit::update_winkit_toml;
        update_winkit_toml(&_implant.implants, version, source);
    }
}

fn update_config(r#mod: &str, implant: &mut Implant) -> anyhow::Result<()> {
    implant.implants.r#mod = r#mod.to_string();
    update_core_config(&implant.basic, &implant.implants);

    let binding = implant
        .build.clone().unwrap();
    let metadata = binding.metadata
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("metadata configuration is required but not found"))?;
    update_resources(metadata);

    update_proto_toml(&implant.basic);
    update_core_toml(&implant.basic, &implant.implants);
    update_beacon_toml(&implant.implants);
    update_module_toml(&implant.implants.modules);
    #[cfg(not(debug_assertions))]
    update_cargo_config_toml(implant)?;
    Ok(())
}

pub fn update_beacon_config(implant: &mut Implant) -> anyhow::Result<()> {
    log_step!("Updating beacon configuration...");
    update_malefic_spites(&implant.implants, &implant.basic.key)?;
    update_config("beacon", implant)?;
    log_success!("Beacon configuration has been updated successfully");
    Ok(())
}

pub fn update_bind_config(implant: &mut Implant) -> anyhow::Result<()> {
    log_step!("Updating bind configuration...");
    update_config("bind", implant)?;
    log_success!("Bind configuration has been updated successfully");
    Ok(())
}

pub fn update_prelude_config(
    yaml_path: &str,
    resources: &str,
    key: &str,
    spite: &str,
) -> anyhow::Result<()> {
    log_step!("Updating prelude configuration...");
    let autorun_yaml = std::fs::read_to_string(yaml_path)?;
    let spites = parse_yaml(&autorun_yaml);
    update_prelude_spites(spites, resources, key, spite)?;
    Ok(())
}

pub fn update_cargo_config_toml(
    implant: &mut Implant
) -> anyhow::Result<()> {
    let force_refresh = implant.build.as_ref().unwrap().refresh_remap_path_prefix;
    update_config_toml(force_refresh);
    Ok(())
}

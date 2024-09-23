use std::fs;

use toml_edit::{DocumentMut, InlineTable, Item, Value};

use crate::{BuildType, Service, Version, CFG_TARGET_OS_WINDOWS, COMMON_TRANSPORT_TCP, COMMON_TRANSPORT_TLS, CONFIG_COMMUNITY, CONFIG_MALEFIC_WIN_KIT_PATH, CONFIG_PREBUILD, CONFIG_PROFESSIONAL, CONFIG_SOURCE, DEFAULT, DEPENDENCICES, FEATURES, MALEFIC_WIN_KIT, PATH, TARGET};

pub fn update_helper_toml(cargo_toml_path: &str, service: Service, version: Version, build_type: BuildType) {
    let cargo_toml_content = fs::read_to_string(cargo_toml_path)
        .expect("Failed to read Cargo.toml file");

    let mut cargo_toml: DocumentMut = cargo_toml_content.parse()
        .expect("Failed to parse Cargo.toml file");
    // Set the default feature to community or professional
    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        if let Some(default_array) = features[&DEFAULT].as_array_mut() {
            match build_type {
                BuildType::Prebuild => {
                    if default_array.iter().find(|x| x.as_str().unwrap() == &CONFIG_PREBUILD.clone()).is_none() {
                        default_array.push(CONFIG_PREBUILD.clone());
                    }
                    default_array.retain(|x| x.as_str().unwrap() != &CONFIG_SOURCE.clone());
                }
                BuildType::Source => {
                    if default_array.iter().find(|x| x.as_str().unwrap() == &CONFIG_SOURCE.clone()).is_none() {
                        default_array.push(CONFIG_SOURCE.clone());
                    }
                    default_array.retain(|x| x.as_str().unwrap() != &CONFIG_PREBUILD.clone());
                }
            }
            match version {
                Version::Community => {
                    if default_array.iter().find(|x| x.as_str().unwrap() == &CONFIG_COMMUNITY.clone()).is_none() {
                        default_array.push(CONFIG_COMMUNITY.clone());
                    }
                    default_array.retain(|x| x.as_str().unwrap() != &CONFIG_PROFESSIONAL.clone());
                }
                Version::Professional => {
                    if default_array.iter().find(|x| x.as_str().unwrap() == &CONFIG_PROFESSIONAL.clone()).is_none() {
                        default_array.push(CONFIG_SOURCE.clone());
                    }
                    default_array.retain(|x| x.as_str().unwrap() != &CONFIG_COMMUNITY.clone());
                }
                _ => panic!("Invalid version is selected.")
            }
        }
    }

    // Set the default feature common
    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        if let Some(default_array) = features[&DEFAULT].as_array_mut() {
            if service.tls {
                if default_array.iter().find(|x| x.as_str().unwrap() == &COMMON_TRANSPORT_TLS.to_string()).is_none() {
                    default_array.push(COMMON_TRANSPORT_TLS.to_string());
                }
                default_array.retain(|x| x.as_str().unwrap() != &COMMON_TRANSPORT_TCP.to_string());
            } else {
                if default_array.iter().find(|x| x.as_str().unwrap() == &COMMON_TRANSPORT_TCP.to_string()).is_none() {
                    default_array.push(COMMON_TRANSPORT_TCP.to_string());
                }
                default_array.retain(|x| x.as_str().unwrap() != &COMMON_TRANSPORT_TLS.to_string());
            }
        }
    }

    if let Some(target) = cargo_toml[&TARGET].as_table_mut() {
        if let Some(target_os) = target[&CFG_TARGET_OS_WINDOWS].as_table_mut() {
            if let Some(dependencies) = target_os[&DEPENDENCICES].as_table_mut() {
                match build_type {
                    BuildType::Prebuild => {
                        dependencies.remove(&MALEFIC_WIN_KIT);
                    }
                    BuildType::Source => {
                        let mut inline_table: InlineTable = InlineTable::default();
                        inline_table.insert(PATH.clone(), Value::from(CONFIG_MALEFIC_WIN_KIT_PATH.clone()));
                        dependencies.insert(&MALEFIC_WIN_KIT.clone(), Item::Value(inline_table.into()));
                    }
                    _ => panic!("Invalid version is selected.")
                }
            }
        }
    }
    fs::write(cargo_toml_path, cargo_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");
    println!("Cargo.toml file {:#?} has been updated.", cargo_toml_path);
}
use std::fs;

use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, Value};

use crate::{CFG_TARGET_OS_WINDOWS, CONFIG_COMMUNITY, CONFIG_MALEFIC_WIN_KIT_PATH, CONFIG_PROFESSIONAL, DEFAULT, DEPENDENCES, DEPENDENCICES, FEATURES, MALEFIC_WIN_KIT, PATH, TARGET};

pub fn update_helper_toml(cargo_toml_path: &str, professional: bool) {
    let cargo_toml_content = fs::read_to_string(cargo_toml_path)
        .expect("Failed to read Cargo.toml file");

    let mut cargo_toml: DocumentMut = cargo_toml_content.parse()
        .expect("Failed to parse Cargo.toml file");
    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        if let Some(default_array) = features[&DEFAULT].as_array_mut() {
            if !professional {
                if default_array.iter().find(|x| x.as_str().unwrap() == &CONFIG_COMMUNITY.clone()).is_none() {
                    default_array.push(CONFIG_COMMUNITY.clone());
                }
                default_array.retain(|x| x.as_str().unwrap() != &CONFIG_PROFESSIONAL.clone());
            } else {
                if default_array.iter().find(|x| x.as_str().unwrap() == &CONFIG_PROFESSIONAL.clone()).is_none() {
                    default_array.push(CONFIG_PROFESSIONAL.clone());
                }
                // 删除community
                default_array.retain(|x| x.as_str().unwrap() != &CONFIG_COMMUNITY.clone());
            }
        }
    }
    if let Some(target) = cargo_toml[&TARGET].as_table_mut() {
        if let Some(target_os) = target[&CFG_TARGET_OS_WINDOWS].as_table_mut() {
            if let Some(dependencies) = target_os[&DEPENDENCICES].as_table_mut() {
                if !professional {
                    dependencies.remove(&MALEFIC_WIN_KIT);
                } else {
                    let mut inline_table: InlineTable = InlineTable::default();
                    inline_table.insert(PATH.clone(), Value::from(CONFIG_MALEFIC_WIN_KIT_PATH.clone()));
                    dependencies.insert(&MALEFIC_WIN_KIT.clone(), Item::Value(inline_table.into()));
                }
            }
        }
    }
    fs::write(cargo_toml_path, cargo_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");
    println!("Cargo.toml file {:#?} has been updated.", cargo_toml_path);
}
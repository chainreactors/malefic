use std::fs;
use toml_edit::{Array, DocumentMut, InlineTable, Item, Value};

use crate::{CFG_TARGET_OS_WINDOWS, CONFIG_MALEFIC_WIN_KIT_PATH, DEFAULT, DEPENDENCICES, FEATURES, MALEFIC_WIN_KIT, PATH, PREBUILD, TARGET, SOURCE};

static DEFAULT_FEATURE: &str = "default-features";
static NANO_FEATURE: &str = "NANO";
static ASM_FEATURE: &str = "ASM";

pub fn update_pulse_toml(source: bool) {
    let config_pulse_toml_path = "malefic-pulse/Cargo.toml";
    let cargo_toml_content = fs::read_to_string(config_pulse_toml_path)
        .expect("Failed to read Cargo.toml file");

    let mut cargo_toml: DocumentMut = cargo_toml_content.parse()
        .expect("Failed to parse Cargo.toml file");

    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        if let Some(default_array) = features[&DEFAULT].as_array_mut() {
            if source {
                // if default_array.iter().find(
                //     |x| x.as_str().unwrap() == SOURCE).is_none() {
                //     default_array.push(SOURCE);
                // }
                default_array.retain(|x| x.as_str().unwrap() != PREBUILD);
            }else{
                if default_array.iter().find(
                    |x| x.as_str().unwrap() == PREBUILD).is_none() {
                    default_array.push(PREBUILD);
                }
                default_array.retain(|x| x.as_str().unwrap() != SOURCE);
            }
        }
    }

    if let Some(target) = cargo_toml[&TARGET].as_table_mut() {
        if let Some(target_os) = target[&CFG_TARGET_OS_WINDOWS].as_table_mut() {
            if let Some(dependencies) = 
                    target_os[&DEPENDENCICES].as_table_mut() {
                if !source {
                    dependencies.remove(&MALEFIC_WIN_KIT);
                }else{
                    let mut inline_table = InlineTable::default();
                    inline_table.insert(
                        PATH,
                        Value::from(CONFIG_MALEFIC_WIN_KIT_PATH)
                    );
                    inline_table.insert(
                        DEFAULT_FEATURE,
                        Value::from(false)
                    );
                    let mut array = Array::default();
                    array.push(NANO_FEATURE);
                    array.push(ASM_FEATURE);
                    inline_table.insert(
                        FEATURES,
                        Value::from(array)
                    );
                    dependencies.insert(
                        &MALEFIC_WIN_KIT,
                        Item::Value(inline_table.into())
                    );
                }
            }
        }
    }

    fs::write(config_pulse_toml_path, cargo_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");
    println!("Cargo.toml file {:#?} has been updated.", config_pulse_toml_path);
}
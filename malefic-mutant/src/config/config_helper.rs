use std::fs;
use toml_edit::{DocumentMut, InlineTable, Item, Value};
use crate::{Version, CFG_TARGET_OS_WINDOWS, COMMUNITY, CONFIG_MALEFIC_WIN_KIT_PATH, 
            DEFAULT, DEPENDENCICES, FEATURES, MALEFIC_WIN_KIT, PATH, PREBUILD, PROFESSIONAL, SOURCE, TARGET};

pub fn update_helper_toml(version: &Version, source: bool) {
    let config_helper_toml_path = "malefic-helper/Cargo.toml";

    let cargo_toml_content = fs::read_to_string(config_helper_toml_path)
        .expect("Failed to read Cargo.toml file");

    let mut cargo_toml: DocumentMut = cargo_toml_content.parse()
        .expect("Failed to parse Cargo.toml file");

    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        if let Some(default_array) = features[&DEFAULT].as_array_mut() {
            if source {
                if default_array.iter().find(
                    |x| x.as_str().unwrap() == SOURCE).is_none() {
                    default_array.push(SOURCE);
                }
                default_array.retain(|x| x.as_str().unwrap() != PREBUILD);
            }else{
                if default_array.iter().find(
                    |x| x.as_str().unwrap() == PREBUILD).is_none() {
                    default_array.push(PREBUILD);
                }
                default_array.retain(|x| x.as_str().unwrap() != SOURCE);
            }

            match version {
                Version::Community => {
                    if default_array.iter().find(
                            |x| x.as_str().unwrap() == COMMUNITY).is_none() {
                        default_array.push(COMMUNITY);
                    }
                    default_array.retain(
                            |x| x.as_str().unwrap() != PROFESSIONAL);
                }
                Version::Professional => {
                    if default_array.iter().find(
                            |x| x.as_str().unwrap() == PROFESSIONAL).is_none() {
                        default_array.push(PROFESSIONAL);
                    }
                    default_array.retain(|x| x.as_str().unwrap() != COMMUNITY);
                }
                _ => panic!("Invalid version is selected."),
            }
        }
    }

    if let Some(target) = cargo_toml[&TARGET].as_table_mut() {
        if let Some(target_os) = target[&CFG_TARGET_OS_WINDOWS].as_table_mut() {
            if let Some(dependencies) = 
                    target_os[&DEPENDENCICES].as_table_mut() {
                if !source {
                    dependencies.remove(&MALEFIC_WIN_KIT);
                }else {
                    let mut inline_table = InlineTable::default();
                    inline_table.insert(
                        PATH.to_string(),
                        Value::from(CONFIG_MALEFIC_WIN_KIT_PATH)
                    );
                    dependencies.insert(
                        &MALEFIC_WIN_KIT,
                        Item::Value(inline_table.into())
                    );
                }
            }
        }
    }

    fs::write(config_helper_toml_path, cargo_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");
    println!("{:#?} has been updated.", config_helper_toml_path);
}

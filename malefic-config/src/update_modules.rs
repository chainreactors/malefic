use std::fs;

use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, Value};

use crate::{CFG_TARGET_OS_WINDOWS, CONFIG_COMMUNITY, CONFIG_MALEFIC_WIN_KIT_PATH, CONFIG_PROFESSIONAL, DEFAULT, DEPENDENCES, DEPENDENCICES, FEATURES, MALEFIC_WIN_KIT, PATH, TARGET};

pub fn update_module_toml(module_toml_path: &str, modules: Vec<String>, professional: bool) {
    let module_toml_content = fs::read_to_string(module_toml_path)
        .expect("Failed to read Cargo.toml file");

    let mut module_toml: DocumentMut = module_toml_content.parse()
        .expect("Failed to parse Cargo.toml file");
    if let Some(features) = module_toml[&FEATURES].as_table_mut() {
        let mut default_array: toml_edit::Array = Array::default();
        if !professional {
            default_array.push(CONFIG_COMMUNITY.clone());
        } else {
            default_array.push(CONFIG_PROFESSIONAL.clone());
        }
        for i in modules {
            default_array.push(i);
        }
        features[&DEFAULT] = Item::Value(default_array.into());
    }

    // remove malefic-win-kit in community :)
        if let Some(target) = module_toml[&TARGET].as_table_mut() {
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

    fs::write(module_toml_path, module_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");

        println!("Cargo.toml file {:#?} has been updated.", module_toml_path);
}

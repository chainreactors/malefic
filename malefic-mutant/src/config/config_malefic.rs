use std::fs;
use toml_edit::{Array, DocumentMut, Item};
use crate::{ImplantConfig, FEATURES};

lazy_static! {
    static ref CONFIG_BEACON_TOML_PATH: String = "malefic/Cargo.toml".to_string();
}


pub fn update_beacon_toml(implant_config: &ImplantConfig) {
    let cargo_toml_content = match fs::read_to_string(CONFIG_BEACON_TOML_PATH.clone()) {
        Ok(content) => content,
        Err(e) => panic!("Failed to read Cargo.toml file at {}: {}", CONFIG_BEACON_TOML_PATH.clone(), e),
    };

    let mut cargo_toml: DocumentMut = match cargo_toml_content.parse() {
        Ok(doc) => doc,
        Err(e) => panic!("Failed to parse Cargo.toml: {}", e),
    };

    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        let default_array = Array::new();
        let mut updated_features = default_array;
        
        match implant_config.r#mod.as_str() {
            "beacon" => {
                updated_features.push("beacon".to_string());
            },
            "bind" => {
                updated_features.push("bind".to_string());
            },
            _ => {}
        }
        
        features["default"] = Item::Value(updated_features.into());
    } else {
        panic!("Failed to find 'features' in Cargo.toml.");
    }

    // 写回更新后的 Cargo.toml 文件
    if let Err(e) = fs::write(CONFIG_BEACON_TOML_PATH.clone(), cargo_toml.to_string()) {
        panic!("Failed to write updated Cargo.toml: {}", e);
    }

    println!("Cargo.toml at {} has been successfully updated.", CONFIG_BEACON_TOML_PATH.clone());
}

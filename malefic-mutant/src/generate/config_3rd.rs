use crate::{log_error, log_success, FEATURES};
use std::fs;
use toml_edit::{Array, DocumentMut};

static CONFIG_3RD_TOML_PATH: &str = "malefic-3rd/Cargo.toml";

pub fn update_3rd_toml(modules: &[String]) {
    let cargo_toml_content =
        fs::read_to_string(CONFIG_3RD_TOML_PATH).expect("Failed to read Cargo.toml file");

    let mut cargo_toml: DocumentMut = cargo_toml_content
        .parse()
        .expect("Failed to parse Cargo.toml file");

    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        let mut default_feature = Array::new();
        for module in modules {
            default_feature.push(module.to_string());
        }
        
        if default_feature.iter().any(|m| m.to_string() == "rem_static")
            && default_feature.iter().any(|m| m.to_string() == "rem_reflection") {
            log_error!("Cannot have both 'rem_static' and 'rem_reflection' features enabled at the same time");
            panic!("Cannot have both 'rem_static' and 'rem_reflection' features enabled at the same time");
        }

        features["default"] = toml_edit::Item::Value(default_feature.into());
    }

    fs::write(CONFIG_3RD_TOML_PATH, cargo_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");
    log_success!("Cargo.toml file {} has been updated", CONFIG_3RD_TOML_PATH);
}

use crate::{log_success, FEATURES};
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
        features["default"] = toml_edit::Item::Value(default_feature.into());
    }

    fs::write(CONFIG_3RD_TOML_PATH, cargo_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");
    log_success!("Cargo.toml file {} has been updated", CONFIG_3RD_TOML_PATH);
}

use std::fs;
use toml_edit::{Array, DocumentMut};
use crate::{Basic, FEATURES};

lazy_static!(
    static ref CONFIG_PROTO_TOML_PATH: String = "malefic-proto/Cargo.toml".to_string();
);

pub fn update_proto_toml(server: &Basic) {
    let cargo_toml_content = fs::read_to_string(CONFIG_PROTO_TOML_PATH.clone())
        .expect("Failed to read Cargo.toml file");

    let mut cargo_toml: DocumentMut = cargo_toml_content.parse()
        .expect("Failed to parse Cargo.toml file");

    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        let mut default_feature = Array::new();
        match server.encryption.as_str() {
            "aes" => {
                default_feature.push("Crypto_AES".to_string());
            },
            "chacha20" => {
                default_feature.push("Crypto_Chacha20".to_string());
            },
            _ => {
                default_feature.push("Crypto_XOR".to_string());
            }
        }
        features["default"] = toml_edit::Item::Value(default_feature.into());
    }
    fs::write(CONFIG_PROTO_TOML_PATH.clone(), cargo_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");
    println!("Cargo.toml file {:#?} has been updated.", CONFIG_PROTO_TOML_PATH.clone());
}
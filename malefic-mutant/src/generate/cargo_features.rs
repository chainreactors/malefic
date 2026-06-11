use std::fs;
use toml_edit::{Array, DocumentMut, Item};

use malefic_gateway::lazy_static;

use crate::config::{ImplantConfig, Version};
use crate::{log_error, log_success, DEFAULT, FEATURES};

// ── Utility functions ──────────────────────────────────────────────

pub fn edit_cargo_toml<F>(path: &str, mutate: F) -> anyhow::Result<()>
where
    F: FnOnce(&mut DocumentMut) -> anyhow::Result<()>,
{
    let content =
        fs::read_to_string(path).map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path, e))?;
    let mut doc: DocumentMut = content
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", path, e))?;
    mutate(&mut doc)?;
    fs::write(path, doc.to_string())
        .map_err(|e| anyhow::anyhow!("Failed to write {}: {}", path, e))?;
    log_success!("Cargo.toml file {} has been updated", path);
    Ok(())
}

pub fn set_default_features(path: &str, features: &[String]) -> anyhow::Result<()> {
    edit_cargo_toml(path, |doc| {
        let feat_table = doc[&FEATURES]
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("No [features] table in {}", path))?;
        let mut arr = Array::new();
        for f in features {
            arr.push(f.as_str());
        }
        feat_table["default"] = Item::Value(arr.into());
        Ok(())
    })
}

pub fn array_ensure(arr: &mut Array, value: &str) {
    if arr.iter().all(|x| x.as_str().unwrap() != value) {
        arr.push(value);
    }
}

// ── Business functions ─────────────────────────────────────────────

static CONFIG_MODULE_TOML_PATH: &str = "malefic-modules/Cargo.toml";
static CONFIG_3RD_TOML_PATH: &str = "malefic-3rd/Cargo.toml";
static CONFIG_FEATURES_TOML_PATH: &str = "malefic-crates/features/Cargo.toml";

pub fn update_features_toml(version: &Version, source: bool, runtime: &str) {
    let build_feat = if source { "source" } else { "prebuild" };
    let ver_feat = version.to_string();
    let runtime_feat = match runtime {
        "smol" => "runtime_smol",
        "async-std" => "runtime_asyncstd",
        _ => "runtime_tokio",
    };
    set_default_features(
        CONFIG_FEATURES_TOML_PATH,
        &[build_feat.to_string(), ver_feat, runtime_feat.to_string()],
    )
    .expect("Failed to update features Cargo.toml");
}

pub fn update_module_toml(modules: &[String], _source: bool) {
    // source/prebuild now propagated from malefic-features via default features
    set_default_features(CONFIG_MODULE_TOML_PATH, modules)
        .expect("Failed to update module Cargo.toml");
}

pub fn update_3rd_toml(modules: &[String]) {
    if modules.iter().any(|m| m == "rem_static") && modules.iter().any(|m| m == "rem_reflection") {
        log_error!(
            "Cannot have both 'rem_static' and 'rem_reflection' features enabled at the same time"
        );
        panic!(
            "Cannot have both 'rem_static' and 'rem_reflection' features enabled at the same time"
        );
    }
    set_default_features(CONFIG_3RD_TOML_PATH, modules).expect("Failed to update 3rd Cargo.toml");
}

pub fn update_pulse_toml(_source: bool) {
    // pulse was refactored to be self-contained no_std shellcode (commit 2775ade),
    // no longer depends on malefic-win-kit, source/prebuild features are no-ops.
}

lazy_static! {
    static ref ALLOCTOR: String = "Alloctor".to_string();
    static ref ALLOCTOR_EX: String = "AlloctorEx".to_string();
    static ref NORMAL: String = "NORMAL".to_string();
    static ref DYNAMIC: String = "DYNAMIC".to_string();
    static ref SYSCALLS: String = "SYSCALLS".to_string();
    static ref CONFIG_WINKIT_TOML_PATH: String = "malefic-win-kit/Cargo.toml".to_string();
    static ref STACK_SPOOFER: String = "StackSpoofer".to_string();
}

pub fn update_winkit_toml(_implant_config: &ImplantConfig, _version: &Version) {
    // Community edition: no win-kit source to configure
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use toml_edit::DocumentMut;

    use super::set_default_features;

    fn temp_manifest_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("malefic-mutant-features-{}.toml", unique));
        path
    }

    #[test]
    fn set_default_features_rewrites_only_selected_modules() {
        let path = temp_manifest_path();
        fs::write(
            &path,
            r#"
[package]
name = "fixture"
version = "0.1.0"

[features]
default = ["full"]
pwd = []
execute_bof = []
pty = []
"#,
        )
        .unwrap();

        let features = vec!["pwd".to_string(), "execute_bof".to_string()];
        set_default_features(path.to_str().unwrap(), &features).unwrap();

        let doc: DocumentMut = fs::read_to_string(&path).unwrap().parse().unwrap();
        let defaults = doc["features"]["default"].as_array().unwrap();
        let values: Vec<String> = defaults
            .iter()
            .map(|item| item.as_str().unwrap().to_string())
            .collect();

        assert_eq!(values, features);

        let _ = fs::remove_file(path);
    }
}

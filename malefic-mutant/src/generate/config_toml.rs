#![allow(dead_code)]
#![allow(unused_imports)]

use crate::{log_error, log_success};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use toml_edit::{Array, DocumentMut, Item, Table, Value};

// Constants
const RANDOM_STRING_LENGTH: usize = 6;
const CONFIG_PATH: &str = ".cargo/config.toml";
const TARGET_KEY: &str = "target";
const CFG_ALL_KEY: &str = "cfg(all())";
const RUSTFLAGS_KEY: &str = "rustflags";

const MALEFIC_DIRS: &[&str] = &[
    "malefic",
    "malefic-modules",
    "malefic-helper",
    "malefic-trait",
    "malefic-mutant",
    "malefic-core",
    "malefic-prelude",
    "malefic-proto",
    "malefic-pulse",
    "malefic-3rd",
];

/// Recursively collect remap flags for all .rs files in the given directory and its subdirectories
fn collect_rs_file_remap_flags(dir: &Path, remap_flags: &mut Vec<String>, current_dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.extension().unwrap_or_default() == "rs" {
            if let Ok(relative_path) = path.strip_prefix(current_dir) {
                let remap_flag = generate_path_remap_flag(&relative_path);
                remap_flags.push(remap_flag);
            }
        } else if path.is_dir() {
            // Recursively process subdirectories
            collect_rs_file_remap_flags(&path, remap_flags, current_dir)?;
        }
    }
    Ok(())
}
/// Collect remap flags for all malefic project source files (src directory and all subdirectories)
fn collect_malefic_project_remap_flags(base_dir: &Path, remap_flags: &mut Vec<String>) -> io::Result<()> {
    let current_dir = std::env::current_dir()?;
    let mut _processed_count = 0;
    let mut _total_files = 0;

    for &dir_name in MALEFIC_DIRS {
        let malefic_dir = base_dir.join(dir_name);
        if malefic_dir.exists() && malefic_dir.is_dir() {
            let src_dir = malefic_dir.join("src");
            if src_dir.exists() && src_dir.is_dir() {
                let initial_count = remap_flags.len();
                // Process src directory and all its subdirectories recursively
                collect_rs_file_remap_flags(&src_dir, remap_flags, &current_dir)?;
                let files_added = remap_flags.len() - initial_count;
                if files_added > 0 {
                    _processed_count += 1;
                    _total_files += files_added;
                }
            }
        }
    }
    Ok(())
}
/// Generate a path remap flag with random target path
fn generate_path_remap_flag(path: &Path) -> String {
    let random_str: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(RANDOM_STRING_LENGTH)
        .map(char::from)
        .collect();

    // Normalize path separators to forward slashes for consistency
    let path_str = path.to_string_lossy().replace('\\', "\\\\");

    format!("--remap-path-prefix={}={}", path_str, random_str)
}

/// Add CARGO_HOME path remap flag if the environment variable exists
fn add_cargo_home_remap_flag(remap_flags: &mut Vec<String>) {
    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        let cargo_home_path = Path::new(&cargo_home);
        let remap_flag = generate_path_remap_flag(cargo_home_path);
        remap_flags.push(remap_flag);
    }
}

/// Collect all remap flags from malefic projects and CARGO_HOME
fn collect_all_remap_flags() -> io::Result<Vec<String>> {
    let mut remap_flags = Vec::new();

    let current_dir = std::env::current_dir()?;
    collect_malefic_project_remap_flags(&current_dir, &mut remap_flags)?;
    add_cargo_home_remap_flag(&mut remap_flags);

    Ok(remap_flags)
}

/// Check if rustflags configuration already exists
fn check_existing_rustflags_config(doc: &DocumentMut) -> bool {
    if let Some(target_table) = doc[TARGET_KEY].as_table() {
        if let Some(cfg_table) = target_table.get(CFG_ALL_KEY) {
            if cfg_table.get(RUSTFLAGS_KEY).is_some() {
                return true;
            }
        }
    }
    false
}

/// Write remap flags to config file (assumes early check already passed)
fn write_config_file(remap_flags: Vec<String>) -> io::Result<()> {
    let config_path = Path::new(CONFIG_PATH);

    // Read existing config or create new one
    let existing_content = if config_path.exists() {
        fs::read_to_string(config_path)?
    } else {
        String::new()
    };

    let mut doc = existing_content.parse::<DocumentMut>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse TOML: {}", e)))?;

    // Create rustflags array
    let mut remap_flags_array = Array::new();
    for flag in remap_flags {
        remap_flags_array.push(Value::from(flag));
    }

    // Ensure target table exists
    if !doc.contains_key(TARGET_KEY) {
        doc[TARGET_KEY] = Item::Table(Table::new());
    }

    // Ensure cfg(all()) table exists
    if !doc[TARGET_KEY].as_table_mut().unwrap().contains_key(CFG_ALL_KEY) {
        doc[TARGET_KEY][CFG_ALL_KEY] = Item::Table(Table::new());
    }

    // Set rustflags
    doc[TARGET_KEY][CFG_ALL_KEY][RUSTFLAGS_KEY] = Item::Value(Value::Array(remap_flags_array));

    // Write to file
    fs::write(config_path, doc.to_string())?;
    log_success!("\"{}\" has been updated successfully", CONFIG_PATH);

    Ok(())
}

/// Check if rustflags configuration already exists in config file
fn check_config_file_early() -> io::Result<bool> {
    let config_path = Path::new(CONFIG_PATH);

    if !config_path.exists() {
        return Ok(false);
    }

    let existing_content = fs::read_to_string(config_path)?;
    let doc = existing_content.parse::<DocumentMut>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse TOML: {}", e)))?;

    Ok(check_existing_rustflags_config(&doc))
}

/// Main function to update the Cargo config.toml with path remapping flags
pub fn update_config_toml(force_refresh: bool) {
    // Early check: if rustflags already exist and not forcing refresh, skip all file traversal
    if !force_refresh {
        match check_config_file_early() {
            Ok(true) => {
                log_success!(" rustflag 'cfg(all())' already exists.");
                return;
            }
            Ok(false) => {
                // Continue with normal processing
            }
            Err(e) => {
                log_error!("Failed to check existing config: {:?}", e);
                return;
            }
        }
    } else {
        log_success!("Force refresh remap-path-prefix, proceeding with config update");
    }

    // Collect remap flags and update config
    match collect_all_remap_flags() {
        Ok(remap_flags) => {
            if remap_flags.is_empty() {
                log_success!("No remap flags to add");
                return;
            }

            if let Err(e) = write_config_file(remap_flags) {
                log_error!("Failed to update config.toml: {:?}", e);
            }
        }
        Err(e) => {
            log_error!("Failed to collect remap flags: {:?}", e);
        }
    }
}

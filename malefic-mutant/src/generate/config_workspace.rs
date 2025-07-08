use std::fs;
use walkdir::WalkDir;
use toml_edit;
use crate::{log_step, log_info, log_warning, log_error, log_success};

static MALEFIC_WIN_KIT: &str = "malefic-win-kit";

pub fn detect_source_mode() -> bool {
    log_step!("Auto-detecting build mode...");
    
    // malefic-mutant 在项目根目录运行，所以检查当前目录下的 malefic-win-kit
    let malefic_win_kit_path = std::path::Path::new(MALEFIC_WIN_KIT);
    log_info!("Checking path: {}", MALEFIC_WIN_KIT);
    
    // 检查目录是否存在
    if !malefic_win_kit_path.exists() {
        log_info!("malefic-win-kit directory not found, using prebuild mode");
        return false;
    }
    
    // 检查目录是否为目录类型
    if !malefic_win_kit_path.is_dir() {
        log_info!("malefic-win-kit is not a directory, using prebuild mode");
        return false;
    }

    let file_count = WalkDir::new(malefic_win_kit_path)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .count();
    
    let source_mode = file_count > 2;
    log_info!("malefic-win-kit directory contains {} files, using {} mode", 
              file_count, 
              if source_mode { "source" } else { "prebuild" });
    
    source_mode
}

pub fn update_workspace_members(source_mode: bool) -> anyhow::Result<()> {
    log_step!("Updating workspace members...");
    
    let workspace_cargo_path = "Cargo.toml";
    let cargo_toml_content = fs::read_to_string(workspace_cargo_path)
        .map_err(|e| {
            log_error!("Failed to read workspace Cargo.toml: {}", e);
            e
        })?;

    let mut cargo_toml: toml_edit::DocumentMut = cargo_toml_content
        .parse()
        .map_err(|e| {
            log_error!("Failed to parse workspace Cargo.toml: {}", e);
            e
        })?;

    if let Some(workspace) = cargo_toml["workspace"].as_table_mut() {
        if let Some(members) = workspace["members"].as_array_mut() {
            let malefic_win_kit_exists = members
                .iter()
                .any(|member| member.as_str() == Some(MALEFIC_WIN_KIT));

            if source_mode && !malefic_win_kit_exists {
                let mut new_item = toml_edit::Value::from(MALEFIC_WIN_KIT);
                new_item.decor_mut().set_suffix(",\n");
                members.push(new_item);

                log_info!("Added '{}' to workspace members", MALEFIC_WIN_KIT);
            } else if !source_mode && malefic_win_kit_exists {
                members.retain(|member| member.as_str() != Some(MALEFIC_WIN_KIT));
                log_info!("Removed '{}' from workspace members", MALEFIC_WIN_KIT);
            } else {
                log_info!("Workspace members already in correct state for {} mode", 
                         if source_mode { "source" } else { "prebuild" });
            }
        } else {
            log_warning!("No 'members' array found in workspace");
        }
    } else {
        log_warning!("No 'workspace' section found in Cargo.toml");
    }

    fs::write(workspace_cargo_path, cargo_toml.to_string())
        .map_err(|e| {
            log_error!("Failed to write workspace Cargo.toml: {}", e);
            e
        })?;

    log_success!("Workspace Cargo.toml has been updated");
    Ok(())
}

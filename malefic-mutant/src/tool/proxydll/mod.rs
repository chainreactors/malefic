// Modular generator is still needed for generate command
pub mod generator;
pub mod packer;

use crate::{log_step, log_success};
pub use generator::update_proxydll;
pub use packer::{ProxyDllPacker, ProxyDllResource};

/// Process ProxyDLL resources after build completion
pub fn process_proxydll_resources(binary_path: &str, _target: &str) -> anyhow::Result<()> {
    use crate::config::Implant;
    use serde_yaml;
    use std::path::Path;

    // Read implant.yaml to get proxydll configuration
    let implant_config_content = std::fs::read_to_string("implant.yaml")?;
    let implant_config: Implant = serde_yaml::from_str(&implant_config_content)?;

    if let Some(loader_config) = implant_config.loader {
        if let Some(proxydll_config) = loader_config.proxydll {
            if proxydll_config.pack_resources {
                log_step!("Processing and packing ProxyDLL resources...");

                let proxy_dll_name = proxydll_config.proxy_dll.clone().unwrap_or_else(|| {
                    Path::new(binary_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown.dll")
                        .to_string()
                });
                let packer = ProxyDllPacker::new(
                    &proxydll_config.resource_dir,
                    Path::new(binary_path)
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .to_str()
                        .unwrap(),
                    &proxy_dll_name,
                    &proxydll_config.proxied_dll,
                );

                // Create output directory
                let output_dir = Path::new("resources/proxydll_out");
                std::fs::create_dir_all(output_dir)?;

                // Process resources and resolve conflicts
                let resources = if Path::new(&proxydll_config.resource_dir).exists() {
                    log_step!("Resource directory found: {}", proxydll_config.resource_dir);
                    packer.process_resources()?
                } else {
                    log_step!(
                        "Warning: Resource directory not found: {}",
                        proxydll_config.resource_dir
                    );
                    Vec::new()
                };
                log_step!("Processed {} resource files", resources.len());

                // Debug: print all processed resources
                for resource in &resources {
                    log_step!(
                        "Resource: {} (path: {}, generated: {})",
                        resource.name,
                        resource.path.display(),
                        resource.is_generated
                    );
                }

                // Copy all files to output directory (excluding generated DLL which will be handled separately)
                for resource in &resources {
                    if !resource.is_generated && resource.path.exists() {
                        let dest_path = output_dir.join(&resource.name);
                        std::fs::copy(&resource.path, &dest_path)?;
                        log_step!(
                            "Copied {} to output directory from {}",
                            resource.name,
                            resource.path.display()
                        );
                    } else if !resource.is_generated {
                        log_step!(
                            "Skipping {} (file not found at {})",
                            resource.name,
                            resource.path.display()
                        );
                    }
                }

                // Copy generated DLL to output directory with correct name
                let proxy_dll_name = proxydll_config.proxy_dll.clone().unwrap_or_else(|| {
                    Path::new(binary_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown.dll")
                        .to_string()
                });
                let dll_dest = output_dir.join(&proxy_dll_name);
                std::fs::copy(binary_path, &dll_dest)?;
                log_step!(
                    "Copied generated DLL as {} to output directory",
                    proxy_dll_name
                );

                // Pack output directory into program.zip
                let zip_path = packer.pack_output_directory(output_dir)?;
                log_success!("Resource pack created: {}", zip_path.display());
            }
        }
    }

    Ok(())
}

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zip::{write::FileOptions, ZipWriter};

#[derive(Debug, Clone)]
pub struct ProxyDllResource {
    pub name: String,
    pub path: PathBuf,
    pub is_generated: bool,
}

pub struct ProxyDllPacker {
    resource_dir: PathBuf,
    output_dir: PathBuf,
    generated_dll_name: String,
    proxied_dll_name: String,
}

impl ProxyDllPacker {
    pub fn new(
        resource_dir: &str,
        output_dir: &str,
        generated_dll_name: &str,
        proxied_dll_name: &str,
    ) -> Self {
        Self {
            resource_dir: PathBuf::from(resource_dir),
            output_dir: PathBuf::from(output_dir),
            generated_dll_name: generated_dll_name.to_string(),
            proxied_dll_name: proxied_dll_name.to_string(),
        }
    }

    /// Process resources and resolve conflicts
    /// Returns list of resources with their target names and source paths
    /// Does NOT modify the source directory - renaming happens during copy
    pub fn process_resources(&self) -> Result<Vec<ProxyDllResource>> {
        let mut resources = Vec::new();

        // Ensure resource directory exists
        if !self.resource_dir.exists() {
            return Err(anyhow!(
                "Resource directory does not exist: {:?}",
                self.resource_dir
            ));
        }

        // Scan resource directory for all files
        let mut existing_files = HashMap::new();
        for entry in fs::read_dir(&self.resource_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                let file_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| anyhow!("Invalid file name: {:?}", path))?
                    .to_string();

                existing_files.insert(file_name.clone(), path);
            }
        }

        // Handle conflict with generated DLL
        if let Some(conflicting_path) = existing_files.get(&self.generated_dll_name) {
            let conflicting_base = self.get_basename(&self.generated_dll_name);
            let target_base = self.get_basename(&self.proxied_dll_name);

            if conflicting_base == target_base {
                // Scenario 1: Same basename (system DLL scenario)
                // The conflict file is likely the original system DLL, will be backed up during copy
                log::info!("Conflict detected: '{}' has same basename as target '{}'. Will backup during copy.",
                          self.generated_dll_name, self.proxied_dll_name);

                // Add as backup resource
                resources.push(ProxyDllResource {
                    name: format!("{}.backup", self.generated_dll_name),
                    path: conflicting_path.clone(),
                    is_generated: false,
                });

                // Remove from existing_files so it won't be added again
                existing_files.remove(&self.generated_dll_name);
            } else {
                // Scenario 2: Different basename (same-directory scenario)
                // Will be renamed to proxied_dll during copy
                log::info!(
                    "Will rename '{}' to '{}' during copy to avoid conflict",
                    self.generated_dll_name,
                    self.proxied_dll_name
                );

                // Add with target name but source path
                resources.push(ProxyDllResource {
                    name: self.proxied_dll_name.clone(),
                    path: conflicting_path.clone(),
                    is_generated: false,
                });

                // Remove from existing_files so it won't be added again
                existing_files.remove(&self.generated_dll_name);
            }
        }

        // Add all remaining files from resource directory
        for (file_name, path) in existing_files {
            resources.push(ProxyDllResource {
                name: file_name,
                path,
                is_generated: false,
            });
        }

        // Add the generated DLL (will be created by generator.rs)
        resources.push(ProxyDllResource {
            name: self.generated_dll_name.clone(),
            path: self.output_dir.join(&self.generated_dll_name),
            is_generated: true,
        });

        Ok(resources)
    }

    /// Pack resources into program.zip
    #[allow(dead_code)]
    pub fn pack_resources(&self, resources: &[ProxyDllResource]) -> Result<PathBuf> {
        let zip_path = self.output_dir.join("program.zip");
        let file = fs::File::create(&zip_path)?;
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        for resource in resources {
            // Skip generated files that don't exist yet
            if resource.is_generated && !resource.path.exists() {
                log::warn!("Generated file not found: {:?}", resource.path);
                continue;
            }

            let file_name = &resource.name;
            zip.start_file(file_name, options)?;

            let file_content = fs::read(&resource.path)?;
            zip.write_all(&file_content)?;

            log::info!("Added to zip: {} -> {}", file_name, zip_path.display());
        }

        zip.finish()?;
        log::info!("Resource pack created: {}", zip_path.display());

        Ok(zip_path)
    }

    /// Pack output directory into program.zip
    pub fn pack_output_directory(&self, output_dir: &Path) -> Result<PathBuf> {
        // Create zip in build output directory instead of proxydll_out
        let zip_path = PathBuf::from(self.output_dir.clone()).join("program.zip");
        let file = fs::File::create(&zip_path)?;
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        // Walk through all files in the output directory
        for entry in fs::read_dir(output_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                let file_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| anyhow!("Invalid file name: {:?}", path))?;

                // Skip program.zip itself
                if file_name == "program.zip" {
                    continue;
                }

                let relative_path = path
                    .strip_prefix(output_dir)
                    .map_err(|_| anyhow!("Failed to create relative path for {:?}", path))?;

                zip.start_file(relative_path.to_str().unwrap_or(file_name), options)?;

                let file_content = fs::read(&path)?;
                zip.write_all(&file_content)?;

                log::info!(
                    "Added to zip: {} -> {}",
                    relative_path.display(),
                    zip_path.display()
                );
            }
        }

        zip.finish()?;
        log::info!("Output directory pack created: {}", zip_path.display());

        Ok(zip_path)
    }

    /// Get base name without extension
    fn get_basename(&self, filename: &str) -> String {
        Path::new(filename)
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or(filename)
            .to_string()
    }
}

use std::path::Path;
use crate::{MetaData, RESOURCES_DIR};

pub fn update_resources(metadata: &MetaData) {
    std::env::set_var("CARGO_CACHE_RUSTC_INFO", "0");
    std::env::set_var("CARGO_PKG_VERSION", "0.0.1");
    std::env::set_var("CARGO_PKG_NAME", "malefic-mutant");
    std::env::set_var("CARGO_PKG_VERSION_MAJOR", "0");
    std::env::set_var("CARGO_PKG_VERSION_MINOR", "0");
    std::env::set_var("CARGO_PKG_VERSION_PATCH", "1");
    let current_dir = std::env::current_dir().unwrap();
    let malefic_config_dir = current_dir.join("malefic-mutant");
    std::env::set_var("CARGO_MANIFEST_DIR", malefic_config_dir);

    let mut rc = winres::WindowsResource::new();
    let base_filepath = Path::new(RESOURCES_DIR);
    let resource_filepath = base_filepath.join("malefic.rc");

    if !&metadata.icon.is_empty() {
        rc.set_icon(&metadata.icon);
    }
    if !&metadata.file_version.is_empty() {
        rc.set("FileVersion", &metadata.file_version);
    }
    if !&metadata.product_version.is_empty() {
        rc.set("ProductVersion", &metadata.product_version);
    }
    if !&metadata.company_name.is_empty() {
        rc.set("CompanyName", &metadata.company_name);
    }
    if !&metadata.product_name.is_empty() {
        rc.set("ProductName", &metadata.product_name);
    }
    if !&metadata.original_filename.is_empty() {
        rc.set("OriginalFilename", &metadata.original_filename);
    }
    if !&metadata.file_description.is_empty() {
        rc.set("FileDescription", &metadata.file_description);
    }
    if !&metadata.internal_name.is_empty() {
        rc.set("InternalName", &metadata.internal_name);
    }
    
    let _ = match rc.write_resource_file(resource_filepath) {
        Ok(_) => {
            println!("Resource file successfully updated.");
            Ok(())
        },
        Err(e) => {
            eprintln!("Failed to update resource file: {}", e);
            Err(e.to_string())
        }
    };
}
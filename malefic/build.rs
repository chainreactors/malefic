extern crate serde;
extern crate serde_json;
use std:: {
    fs::File,
    io:: {
        Write,
        Read
    }
};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref CONFIG_YAML_FILE: &'static str = "../config.yaml";
}

#[derive(Serialize, Deserialize)]
struct Implant {
    implants: ImplantConfig,
}


#[derive(Serialize, Deserialize)]
struct ImplantConfig {
    modules: Vec<String>,
    metadata: MetaData,
}

#[derive(Serialize, Deserialize)]
struct MetaData {
    remap_path: String,
    icon: String,
    compile_time: String,
    file_version: String,
    product_version: String,
    company_name: String,
    product_name: String,
    original_filename: String,
    file_description: String,
    internal_name: String
}



fn set_env() {
    std::env::set_var("CARGO_CACHE_RUSTC_INFO", "0");
}


fn modify_win_res(metadata: &MetaData) {
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        if !&metadata.icon.is_empty() {
            res.set_icon(&metadata.icon);
        }
        if !&metadata.file_version.is_empty() {
            res.set("FileVersion", &metadata.file_version);
        }
        if !&metadata.product_version.is_empty() {
            res.set("ProductVersion", &metadata.product_version);
        }
        if !&metadata.company_name.is_empty() {
            res.set("CompanyName", &metadata.company_name);
        }
        if !&metadata.product_name.is_empty() {
            res.set("ProductName", &metadata.product_name);
        }
        if !&metadata.original_filename.is_empty() {
            res.set("OriginalFilename", &metadata.original_filename);
        }
        if !&metadata.file_description.is_empty() {
            res.set("FileDescription", &metadata.file_description);
        }
        if !&metadata.internal_name.is_empty() {
            res.set("InternalName", &metadata.internal_name);
        }
        res.compile().unwrap();
    }
}

fn parse_config_yaml() -> Implant {
    let mut file = File::open(CONFIG_YAML_FILE.to_string()).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).expect("read config file error");

    let implant_server: Implant = 
        serde_yaml::from_str(&content).expect("parse config file error");

    implant_server
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=path/to/Cargo.lock");
    println!("test build!");
    set_env();
    let implant_server = parse_config_yaml();
    modify_win_res(&implant_server.implants.metadata);
}
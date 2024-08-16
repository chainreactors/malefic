#[macro_use]
extern crate lazy_static;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use serde_json::Value as JsonValue;
use jsonschema::{JSONSchema};
use std::fs;
use std::ops::Add;
use std::process;
use update_helper::update_helper_toml;
use update_winkit::update_winkit_toml;
use update_modules::update_module_toml;
use crate::update_core::{update_core, update_core_toml};


mod update_helper;
mod update_modules;
mod update_winkit;
mod update_core;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Implant {
    server: Service,
    implants: ImplantConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Service {
    name: String,
    urls: Vec<String>,
    proxy: String,
    interval: u64,
    jitter: u64,
    ca: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImplantConfig {
    register_info: bool,
    modules: Vec<String>,
    metadata: MetaData,
    apis: Apis,
    alloctor: Alloctor,
    sleep_mask: bool,
    sacrifice_process: bool,
    fork_and_run: bool,
    hook_exit: bool,
    thread_stack_spoofer: bool,
    pe_signature_modify: PESignatureModify,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Apis {
    level: String,
    priority: ApisPriority
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApisPriority {
    normal: NormalPriority,
    dynamic: DynamicPriority,
    syscalls: SyscallPriority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NormalPriority {
    enable: bool,
    r#type: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DynamicPriority {
    enable: bool,
    r#type: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyscallPriority {
    enable: bool,
    r#type: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Alloctor {
    inprocess: String,
    crossprocess: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
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
    internal_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PESignatureModify {
    feature: bool,
    modify: PESModify,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PESModify {
    magic: String,
    signature: String,
}

lazy_static! {
    static ref CONFIG_COMMUNITY: String = "community".to_string();
    static ref CONFIG_PROFESSIONAL: String = "professional".to_string();
    static ref CONFIG_PROFESSIONAL_TEMPLATE: String = "professional_template".to_string();
    static ref CONFIG_YAML_PATH: String = "config.yaml".to_string();
    static ref CONFIG_SCHEMA_PATH: String = "config_schema.json".to_string();
    static ref CONFIG_CORE_TOML_PATH: String = "malefic/Cargo.toml".to_string();
    static ref CONFIG_WINKIT_TOML_PATH: String = "malefic-win-kit/Cargo.toml".to_string();
    static ref CONFIG_MODULE_TOML_PATH: String = "malefic-modules/Cargo.toml".to_string();
    static ref CONFIG_HELPER_TOML_PATH: String = "malefic-helper/Cargo.toml".to_string();
    static ref CONFIG_MALEFIC_WIN_KIT_PATH: String = "../malefic-win-kit".to_string();

    static ref CFG_TARGET_OS_WINDOWS: String = "cfg(target_os = \"windows\")".to_string();

    static ref MALEFIC_WIN_KIT: String = "malefic-win-kit".to_string();
    static ref PATH: String = "path".to_string();
    static ref TARGET: String = "target".to_string();
    static ref DEFAULT: String = "default".to_string();
    static ref FEATURES: String = "features".to_string();
    static ref DEPENDENCES: String = "dependences".to_string();
    static ref DEPENDENCICES: String = "dependencies".to_string();
    static ref ALLOCTOR: String = "Alloctor".to_string();
    static ref ALLOCTOR_EX: String = "AlloctorEx".to_string();
    static ref NORMAL:String = "NORMAL".to_string();
    static ref DYNAMIC: String = "DYNAMIC".to_string();
    static ref SYSCALLS: String = "SYSCALLS".to_string();
}


fn load_yaml_config(yaml_path: &str) -> Implant {
    let yaml_content = fs::read_to_string(yaml_path)
        .expect("Failed to read YAML file");
    let config: Implant = serde_yaml::from_str(&yaml_content)
        .expect("Failed to parse YAML file");
    config
}

fn validate_yaml_config(yaml_path: &str, schema_path: &str) {
    let yaml_content = fs::read_to_string(yaml_path)
        .expect("Failed to read YAML file");
    let yaml_value: YamlValue = serde_yaml::from_str(&yaml_content)
        .expect("Failed to parse YAML file");
    let json_value = serde_json::to_value(&yaml_value)
        .expect("Failed to convert YAML to JSON");

    let schema_content = fs::read_to_string(schema_path)
        .expect("Failed to read JSON schema file");
    let schema: JsonValue = serde_json::from_str(&schema_content)
        .expect("Failed to parse JSON schema");

    let compiled_schema = JSONSchema::compile(&schema)
        .expect("Invalid JSON Schema");

    let result = compiled_schema.validate(&json_value);
    if let Err(errors) = result {
        for error in errors {
            println!("Validation error: {}", error);
        }
        process::exit(1);
    }

    println!("YAML configuration is valid.");
}

fn main() {
    // 读取命令行参数
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} community/professional", args[0]);
        process::exit(1);
    }
    let professional: bool;
    
    if CONFIG_COMMUNITY.eq(&args[1]) {
        println!("Community version is selected.");
        professional = false;
    } else if CONFIG_PROFESSIONAL.eq(&args[1]) {
        professional = true;
        println!("Professional version is selected.");
    } else {
        println!("Invalid version is selected.");
        process::exit(1);
    }

    let config = load_yaml_config(&CONFIG_YAML_PATH);
    validate_yaml_config(&CONFIG_YAML_PATH, &CONFIG_SCHEMA_PATH);
    update_core(config.server.clone());
    update_core_toml(&CONFIG_CORE_TOML_PATH, config.implants.clone(), professional);
    update_winkit_toml(&CONFIG_WINKIT_TOML_PATH, config.implants.clone(), professional);
    update_module_toml(&CONFIG_MODULE_TOML_PATH, config.implants.modules.clone(), professional);
    update_helper_toml(&CONFIG_HELPER_TOML_PATH, professional);
}

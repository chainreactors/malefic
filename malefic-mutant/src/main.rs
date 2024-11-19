#[allow(deprecated)]
#[macro_use]
extern crate lazy_static;
use clap::{Parser, ValueEnum};
use config::{
    update_beacon_config, 
    update_bind_config, 
    update_prelude_config, 
    update_pulse_config,
    update_common_config
};
use generator::*;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use serde_json::Value as JsonValue;
use jsonschema::Validator;

use strum_macros::{Display, EnumString};
use std::{fs, process};
use std::collections::HashMap;
use crate::cmd::{BuildCommands, Cli, Commands, GenerateCommands};

mod config;
mod generator;
mod cmd;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Implant {
    basic: Basic,
    implants: ImplantConfig,
    metadata: MetaData,
    pulse: Pulse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Basic {
    name: String,
    targets: Vec<String>,
    protocol: String,
    tls: bool,
    proxy: String,
    interval: u64,
    jitter: f64,
    ca: String,
    encryption: String,
    key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pulse {
    flags: Flags,
    target: String,
    protocol: String,
    encryption: String,
    key: String,
    http: HttpHeader,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HttpHeader {
    method: String,
    path: String,
    version: String,
    headers: HashMap<String, String>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImplantConfig {
    r#mod: String,
    register_info: bool,
    hot_load: bool,
    modules: Vec<String>,
    flags: Flags,
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
struct Flags {
    start: u32,// Acutally it's a u8
    end: u32, // Actually it's a u8
    magic: String,
    artifact_id : u32,
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

#[derive(Debug, Clone, Copy, EnumString, Display, ValueEnum)]
pub enum Version {
    #[strum(serialize = "community")]
    Community,
    #[strum(serialize = "professional")]
    Professional,
    #[strum(serialize = "inner")]
    Inner,
}

#[derive(Debug, Clone, Copy, EnumString, Display)]
pub enum GenerateArch {
    #[strum(serialize = "x64")]
    X64,
    #[strum(serialize = "x86")]
    X86,
}

#[derive(Debug, Clone, Copy, EnumString, Display)]
pub enum TransportProtocolType {
    #[strum(serialize = "tcp")]
    Tcp,
    #[strum(serialize = "http")]
    Http,
    // #[strum(serialize = "https")]
    // Https,
}

#[derive(Debug, Clone, Copy, EnumString, Display)]
pub enum Platform {
    #[strum(serialize = "win")]
    Win,
    #[strum(serialize = "linux")]
    Linux,
    #[strum(serialize = "darwin")]
    Darwin,
}

static CONFIG_INNER_TEMPLATE: &str = "inner_template";
static CONFIG_PROFESSIONAL_TEMPLATE: &str = "professional_template";
static CONFIG_YAML_PATH: &str = "config.yaml";
static CONFIG_SCHEMA_PATH: &str = "config_lint.json";
static MALEFIC_WIN_KIT: &str = "malefic-win-kit";
static CONFIG_MALEFIC_WIN_KIT_PATH: &str = "../malefic-win-kit";

static CFG_TARGET_OS_WINDOWS: &str = "cfg(target_os = \"windows\")";
static PATH: &str = "path";
static TARGET: &str = "target";
static DEFAULT: &str = "default";
static FEATURES: &str = "features";
static PREBUILD: &str = "prebuild";
static SOURCE: &str = "source";
static COMMUNITY: &str = "community";
static PROFESSIONAL: &str = "professional";
// static DEPENDENCES: &str = "dependences";
static DEPENDENCICES: &str = "dependencies";

static RESOURCES_DIR: &str = "./resources/";

fn load_yaml_config(yaml_path: &str) -> anyhow::Result<Implant> {
    let yaml_content = fs::read_to_string(yaml_path)?;
    let config: Implant = serde_yaml::from_str(&yaml_content)?;
    Ok(config)
}

fn validate_yaml_config(yaml_path: &str, schema_path: &str) -> anyhow::Result<()> {
    let yaml_content = fs::read_to_string(yaml_path)?;
    let yaml_value: YamlValue = serde_yaml::from_str(&yaml_content)?;
    let json_value = serde_json::to_value(&yaml_value)?;

    let schema_content = fs::read_to_string(schema_path)?;
    let schema: JsonValue = serde_json::from_str(&schema_content)
        .expect("Failed to parse JSON schema");

    // 使用 Validator::new 编译 schema
    let compiled_schema = Validator::new(&schema)
        .expect("Invalid JSON Schema");

    // 直接检查 validate 的 Result
    if let Err(error) = compiled_schema.validate(&json_value) {
        println!("Schema validation error: {}", error);
        process::exit(1);
    }

    println!("YAML configuration is valid.");
    Ok(())
}


// Define the CLI structure

fn parse_generate(
    yaml_config: &mut Implant,
    config: &GenerateCommands,
    version: Version,
    source: bool,
) -> anyhow::Result<()> {
    update_common_config(yaml_config, &version, source);
    match config {
        GenerateCommands::Beacon => update_beacon_config(yaml_config),
        GenerateCommands::Bind => update_bind_config(yaml_config),
        GenerateCommands::Prelude { yaml_path, resources, key } => {
            update_prelude_config(yaml_path, resources, key)
        }
        GenerateCommands::Modules { modules } => {
            if !modules.is_empty() {
                yaml_config.implants.modules = modules.split(",").map(|x| x.to_string()).collect();
                println!("Modules: {:?}", yaml_config.implants.modules);
            }
            update_beacon_config(yaml_config)
        }
        GenerateCommands::Pulse { platform, arch } => {
            update_pulse_config(source)?;
            pulse_generate(yaml_config.pulse.clone(), *platform, *arch, version, source)
        }
    }
}

fn parse_build(
    generate: &BuildCommands
) -> anyhow::Result<()> {
    match generate {
        BuildCommands::TinyTools(_tiny_tools) => {
            println!("TinyTools");
            Ok(())
        },
        BuildCommands::SRDI { src_path, platform, arch, target_path, function_name, userdata_path } => {
            link_srdi_generator(
                src_path, *platform, *arch, target_path, function_name, userdata_path)
        }
    }
}

fn main() -> anyhow::Result<()> {
    let mut implant_config = load_yaml_config(CONFIG_YAML_PATH)?;

    let cli = Cli::parse();
    match &cli.command {
        Commands::Generate {version, source, command } => {
            validate_yaml_config(CONFIG_YAML_PATH, CONFIG_SCHEMA_PATH)?;
            parse_generate(&mut implant_config, command, *version, *source)
        },
        Commands::Build(generate) => {
            parse_build(generate)
        }
    }
}
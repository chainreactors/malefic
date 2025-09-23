#[allow(deprecated)]
#[macro_use]
extern crate lazy_static;
use clap::Parser;
use cmd::SrdiType;
use generate::{
    update_beacon_config, update_bind_config, update_common_config, update_prelude_config,
    update_pulse_config,
};

use build::*;
use jsonschema::Validator;
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;

use crate::build::payload::build_payload;
use crate::cmd::{BuildCommands, Cli, Commands, GenerateCommands, PayloadType, Tool};
use std::{fs, process};
use strum_macros::{Display, EnumString};
use config::{Implant, Version};

mod build;
mod cmd;
mod generate;
mod logger;
mod tool;
mod config;

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
        log_error!("Schema validation '{}' failed: {}",error.instance_path, error);
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
            yaml_path: autorun_yaml_path,
            resources,
            key,
            spite,
        } => {
            log_info!("Generating prelude configuration");
            update_prelude_config(yaml_config,autorun_yaml_path, resources, key, spite)
        }
        GenerateCommands::Modules { module } => {
            if !module.is_empty() {
                yaml_config.implants.modules = module.split(",").map(|x| x.to_string()).collect();
                log_info!("Using modules: {:?}", yaml_config.implants.modules);
            }
            update_beacon_config(yaml_config)
        }
        GenerateCommands::Pulse { platform, arch } => {
            log_info!("Generating pulse configuration for {} {}", platform, arch);
            update_pulse_config(source)?;
            let pulse_config = yaml_config
                .pulse
                .clone()
                .ok_or_else(|| anyhow::anyhow!("pulse configuration is required but not found"))?;
            pulse_generate(pulse_config, *platform, *arch, version, source)
        }
        GenerateCommands::ProxyDLL { input, hijacked_exports, native_thread } => {
            log_info!("Generating ProxyDLL for {}", input);
            let exports: Vec<&str> = if hijacked_exports.is_empty() {
                Vec::new()
            } else {
                hijacked_exports.split(',').map(|s| s.trim()).collect()
            };
            
            tool::proxydll::generator::update_proxydll(
                input,
                &exports,
                *native_thread,
                false, // hijack_current_thread
                false, // link_runtime
            )
        }
    };

    if result.is_ok() {
        log_success!("Configuration generation completed successfully");
    }
    result
}

fn parse_build(config: &mut Implant, build: &BuildCommands, target: &String) -> anyhow::Result<()> {
    let build_config = config
        .build
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("build configuration is required but not found"))?;

    let result = match build {
        BuildCommands::Malefic => build_payload(build_config, &PayloadType::MALEFIC, target, None),
        BuildCommands::Modules { module } => {
            use crate::generate::update_module_toml;
            // 1. 判断命令行参数是否为空，决定用 config 还是命令行
            let mut modules: Vec<String> = Vec::new();
            if !module.is_empty() {
                modules.extend(module.split(',').map(|s| s.trim().to_string()));
                config.implants.modules = modules.clone();
            } else {
                modules = config.implants.modules.clone();
            }
            // 2. 更新 features 到 toml
            update_module_toml(&modules);
            // 3. 编译 malefic-modules
            build_payload(build_config, &PayloadType::MODULES, target, Some(&modules))
        }
        BuildCommands::Modules3rd { module } => {
            use crate::generate::update_3rd_toml;
            // 1. 判断命令行参数是否为空，决定用 config 还是命令行
            let mut third_modules: Vec<String> = Vec::new();
            if !module.is_empty() {
                third_modules.extend(module.split(',').map(|s| s.trim().to_string()));
                config.implants.third_modules = third_modules.clone();
            } else {
                third_modules = config.implants.third_modules.clone();
            }
            third_modules.push("as_cdylib".to_string());
            update_3rd_toml(&third_modules);
            build_payload(
                build_config,
                &PayloadType::THIRD,
                target,
                Some(&third_modules),
            )
        }
        BuildCommands::Pulse => build_payload(build_config, &PayloadType::PULSE, target, None),
        BuildCommands::Prelude => build_payload(build_config, &PayloadType::PRELUDE, target, None),
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
        Tool::STRIP {
            input,
            output,
            custom_paths,
        } => {
            use crate::tool::strip::strip_paths_from_binary;
            
            log_step!("Stripping paths from binary...");
            log_info!("Input: {}, Output: {}", input, output);

            let custom_path_list: Vec<String> = if custom_paths.is_empty() {
                Vec::new()
            } else {
                custom_paths.split(',').map(|s| s.trim().to_string()).collect()
            };

            if !custom_path_list.is_empty() {
                log_info!("Custom paths: {:?}", custom_path_list);
            }

            let result = strip_paths_from_binary(input, output, &custom_path_list);

            if result.is_ok() {
                log_success!("Path stripping completed successfully");
            }
            result
        }
        Tool::OBJCOPY {
            output_format,
            input,
            output,
        } => {
            use crate::tool::pe::PEObjCopy;
            
            log_step!("Converting binary file...");
            log_info!("Input: {}, Output: {}, Format: {}", input, output, output_format);

            let result = match output_format.as_str() {
                "binary" => PEObjCopy::extract_binary(input, output),
                _ => {
                    log_error!("Unsupported output format: {}", output_format);
                    log_info!("Supported formats: binary");
                    Err(anyhow::anyhow!("Unsupported output format: {}", output_format))
                }
            };

            if result.is_ok() {
                log_success!("Binary conversion completed successfully");
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
            config,
            command,
            source,
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
            parse_build(&mut implant_config, command, target)
        }
        Commands::Tool(tool) => parse_tool(tool),
    }
}

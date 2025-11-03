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
use crate::cmd::{
    BuildCommands, Cli, Commands, GenerateCommands, PayloadType, SigForgeCommands, Tool,
};
use crate::tool::sigforge::SignatureRemover;
use config::{Implant, Version};
use std::{fs, path::Path, process};
use strum_macros::{Display, EnumString};

mod build;
mod cmd;
mod config;
mod generate;
mod logger;
mod tool;

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
        log_error!(
            "Schema validation '{}' failed: {}",
            error.instance_path,
            error
        );
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
            yaml_path: prelude_yaml_path,
            resources,
            key,
            spite,
        } => {
            log_info!("Generating prelude configuration");
            update_prelude_config(yaml_config, prelude_yaml_path, resources, key, spite)
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
        GenerateCommands::ProxyDLL {
            raw_dll,
            proxied_dll,
            proxy_dll,
            hijacked_exports,
            native_thread,
        } => {
            // Try to get config from yaml, command line args override config file
            let proxydll_config = yaml_config
                .loader
                .as_ref()
                .and_then(|l| l.proxydll.as_ref());

            // Determine actual values (CLI args > config file)
            let raw_dll_path = if !raw_dll.is_empty() {
                raw_dll.clone()
            } else if let Some(cfg) = proxydll_config {
                cfg.raw_dll.clone()
            } else {
                return Err(anyhow::anyhow!(
                    "raw_dll is required (use -r or configure in yaml)"
                ));
            };

            let proxied_dll_path = if !proxied_dll.is_empty() {
                proxied_dll.clone()
            } else if let Some(cfg) = proxydll_config {
                cfg.proxied_dll.clone()
            } else {
                return Err(anyhow::anyhow!(
                    "proxied_dll is required (use -p or configure in yaml)"
                ));
            };

            // Proxy DLL name: CLI > config > extract from proxied_dll
            let proxy_dll_name = if let Some(out) = proxy_dll {
                out.clone()
            } else if let Some(cfg) = proxydll_config {
                cfg.proxy_dll.clone().unwrap_or_else(|| {
                    std::path::Path::new(&cfg.proxied_dll)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(&cfg.proxied_dll)
                        .to_string()
                })
            } else {
                std::path::Path::new(&proxied_dll_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&proxied_dll_path)
                    .to_string()
            };

            let hijacked_funcs = if !hijacked_exports.is_empty() {
                hijacked_exports.clone()
            } else if let Some(cfg) = proxydll_config {
                cfg.proxyfunc.clone()
            } else {
                String::new()
            };

            let use_native_thread =
                *native_thread || proxydll_config.map_or(false, |c| c.native_thread);
            let use_block = proxydll_config.map_or(false, |c| c.block);
            let _resource_dir = proxydll_config
                .map(|c| c.resource_dir.clone())
                .unwrap_or_else(|| "resources/proxydll".to_string());
            let _pack_resources = proxydll_config.map_or(false, |c| c.pack_resources);

            // Use implant.prelude configuration to determine if prelude should be enabled
            // Clone the prelude path to avoid borrow issues
            let prelude_path = yaml_config.implants.prelude.clone();
            let use_prelude = !prelude_path.is_empty();

            // Generate spites if prelude is configured
            if use_prelude {
                log_step!("Generating spites for ProxyDLL prelude...");
                update_prelude_config(
                    yaml_config,
                    &prelude_path,
                    "resources",
                    "maliceofinternal",
                    "spite.bin",
                )?;
            }

            log_info!("Generating ProxyDLL for {}", raw_dll_path);
            let exports: Vec<&str> = if hijacked_funcs.is_empty() {
                Vec::new()
            } else {
                hijacked_funcs.split(',').map(|s| s.trim()).collect()
            };

            // Generate the proxy DLL
            tool::proxydll::generator::update_proxydll(
                &raw_dll_path,
                &proxied_dll_path,
                &proxy_dll_name,
                &exports,
                use_native_thread,
                use_block,
                use_prelude,
            )?;

            Ok(())
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
        BuildCommands::ProxyDll => {
            build_payload(build_config, &PayloadType::PROXYDLL, target, None)
        }
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
                custom_paths
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect()
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
            log_info!(
                "Input: {}, Output: {}, Format: {}",
                input,
                output,
                output_format
            );

            let result = match output_format.as_str() {
                "binary" => PEObjCopy::extract_binary(input, output),
                _ => {
                    log_error!("Unsupported output format: {}", output_format);
                    log_info!("Supported formats: binary");
                    Err(anyhow::anyhow!(
                        "Unsupported output format: {}",
                        output_format
                    ))
                }
            };

            if result.is_ok() {
                log_success!("Binary conversion completed successfully");
            }
            result
        }
        Tool::SigForge { command } => parse_sigforge(command),
        Tool::Patch {
            file,
            name,
            key,
            server_address,
            output,
            xor_key,
        } => {
            use crate::tool::patch::{
                batch_patch_binary, BatchPatchOptions, FieldPatch, PatchField,
            };

            // Collect patches
            let mut patches = Vec::new();

            let resolved_xor_key = resolve_patch_xor_key(xor_key.as_deref())?;
            let xor_key_bytes = resolved_xor_key.as_bytes().to_vec();

            if let Some(name_val) = name {
                patches.push(FieldPatch {
                    field: PatchField::Name,
                    value: name_val.clone(),
                    is_hex: false,
                    default_value: None,
                });
            }

            if let Some(key_val) = key {
                patches.push(FieldPatch {
                    field: PatchField::Key,
                    value: key_val.clone(),
                    is_hex: false,
                    default_value: Some(resolved_xor_key.clone()),
                });
            }

            if let Some(addr) = server_address {
                patches.push(FieldPatch {
                    field: PatchField::ServerAddress,
                    value: addr.clone(),
                    is_hex: false,
                    default_value: None,
                });
            }

            if patches.is_empty() {
                log_error!("No fields specified to patch. Use --name, --key, or --server-address");
                return Err(anyhow::anyhow!("no fields specified for patching"));
            }

            log_step!("Patching {} field(s) in {}", patches.len(), file);
            for patch in &patches {
                log_info!("  {} = {}", patch.field.label(), patch.value);
            }

            let options = BatchPatchOptions {
                file: file.clone(),
                patches,
                output: output.clone(),
                xor_key: xor_key_bytes,
            };

            let outcome = batch_patch_binary(&options)?;
            let overwritten = outcome.output_path == std::path::PathBuf::from(file);

            log_success!(
                "Successfully patched {} field(s)",
                outcome.patched_fields.len()
            );
            for (field, offset) in &outcome.patched_fields {
                log_info!(
                    "  {} at offset 0x{:X} ({} decimal)",
                    field.label(),
                    offset,
                    offset
                );
            }

            if overwritten {
                log_info!("Original file overwritten in-place");
            } else {
                log_info!("Patched file written to {}", outcome.output_path.display());
            }
            Ok(())
        }
    }
}

fn parse_sigforge(command: &SigForgeCommands) -> anyhow::Result<()> {
    use crate::tool::sigforge::{SignatureExtractor, SignatureInjector};

    match command {
        SigForgeCommands::Extract { input, output } => {
            log_step!("Extracting signature from {}", input);

            let signature = SignatureExtractor::extract_from_file(&input)?;

            let output_path = output
                .as_ref()
                .map(|s| s.clone())
                .unwrap_or_else(|| format!("{}_sig", input));
            SignatureExtractor::save_signature_to_file(&signature, &output_path)?;

            log_success!("Signature extracted to: {}", output_path);
            log_info!("Signature size: {} bytes", signature.len());
            Ok(())
        }

        SigForgeCommands::Copy {
            source,
            target,
            output,
        } => {
            log_step!("Copying signature from {} to {}", source, target);

            let output_path =
                SignatureInjector::copy_signature(&source, &target, output.as_deref())?;

            log_success!("Signature copied to: {}", output_path);
            Ok(())
        }

        SigForgeCommands::Inject {
            signature,
            target,
            output,
        } => {
            log_step!("Injecting signature from {} into {}", signature, target);

            let output_path =
                SignatureInjector::inject_from_file(&signature, &target, output.as_deref())?;

            log_success!("Signature injected to: {}", output_path);
            Ok(())
        }

        SigForgeCommands::Remove { input, output } => {
            log_step!("Removing signature from {}", input);

            let _output_path = output
                .as_ref()
                .map(|s| s.clone())
                .unwrap_or_else(|| format!("{}_unsigned", input));

            let output_path = SignatureRemover::remove_signature(&input, output.as_deref())?;

            log_info!("Signature removal functionality to be implemented");
            log_success!("Signature removed, output: {}", output_path);
            Ok(())
        }
        SigForgeCommands::Check { input } => {
            let is_signed = SignatureExtractor::check_if_signed(&input)?;

            if is_signed {
                log_success!("File {} is signed", input);
            } else {
                log_success!("File {} is not signed", input);
            }
            Ok(())
        }
    }
}

fn resolve_patch_xor_key(cli_value: Option<&str>) -> anyhow::Result<String> {
    if let Some(value) = cli_value {
        return Ok(value.to_string());
    }

    if let Some(key) = read_key_from_implant_yaml()? {
        if !key.is_empty() {
            return Ok(key);
        }
    }

    Ok("maliceofinternal".to_string())
}

fn read_key_from_implant_yaml() -> anyhow::Result<Option<String>> {
    let path = Path::new("implant.yaml");
    if !path.exists() {
        return Ok(None);
    }

    let yaml_content = fs::read_to_string(path)?;
    let yaml_value: YamlValue = serde_yaml::from_str(&yaml_content)?;
    Ok(yaml_value
        .get("basic")
        .and_then(|basic| basic.get("key"))
        .and_then(|key| key.as_str())
        .map(|value| value.to_string()))
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

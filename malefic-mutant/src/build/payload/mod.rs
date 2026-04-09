#![allow(non_camel_case_types)]
use crate::config::BuildConfig;
use crate::tool::strip::strip_paths_from_binary;
use crate::{cmd::PayloadType, log_error, log_step, log_success, log_warning};
use duct::cmd;
use std::str::FromStr;
use strum_macros::Display;

static OLLVM_FLGAS: &str = "resources/ollvm-flags";

#[derive(Clone, Display)]
pub enum OllvmAllow {
    #[strum(serialize = "x86_64-pc-windows-gnu")]
    X86_64_WINDOWS_GNU,
    #[strum(serialize = "x86_64-unknown-linux-gnu")]
    X86_64_LINUX_GNU,
    // #[strum(serialize = "i686-pc-windows-gnu")]
    // I686_WINDOWS_GNU,
    // #[strum(serialize = "i686-unknown-linux-gnu")]
    // I686_LINUX_GNU,
}

impl FromStr for OllvmAllow {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "x86_64-pc-windows-gnu" => Ok(OllvmAllow::X86_64_WINDOWS_GNU),
            "x86_64-unknown-linux-gnu" => Ok(OllvmAllow::X86_64_LINUX_GNU),
            // "i686-pc-windows-gnu" => Ok(OllvmAllow::I686_WINDOWS_GNU),
            // "i686-unknown-linux-gnu" => Ok(OllvmAllow::I686_LINUX_GNU),
            _ => Err(format!("'{}' is not a valid value for OllvmAllow", s)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildProfile {
    Dev,
    Release,
}

impl BuildProfile {
    pub fn from_dev(dev: bool) -> Self {
        if dev {
            Self::Dev
        } else {
            Self::Release
        }
    }

    pub fn is_release(self) -> bool {
        matches!(self, Self::Release)
    }

    pub fn output_dir(self) -> &'static str {
        match self {
            Self::Dev => "debug",
            Self::Release => "release",
        }
    }
}

pub fn build_payload(
    config: &mut BuildConfig,
    payload_type: &PayloadType,
    target: &String,
    features: Option<&Vec<String>>,
    build_lib: bool,
    profile: BuildProfile,
) -> anyhow::Result<()> {
    let mut args: Vec<String> = Vec::new();
    let package = match payload_type {
        PayloadType::THIRD => "malefic-3rd".to_string(),
        _ => payload_type.to_string(),
    };

    let target_platform = detect_target_platform(target)?;
    let build_lib = normalize_build_kind(payload_type, build_lib, target_platform)?;

    let ollvm_flag = std::fs::File::open(OLLVM_FLGAS);
    let ollvm_allowed = config.ollvm.enable && OllvmAllow::from_str(target).is_ok();
    let use_ollvm = profile.is_release() && ollvm_allowed;

    if config.ollvm.enable && !profile.is_release() {
        log_warning!("--dev disables OLLVM; falling back to the standard cargo backend");
    }

    if use_ollvm {
        if ollvm_flag.is_err() {
            std::fs::File::create(OLLVM_FLGAS)?;
        }
        let _ = cmd("rustup", ["default", "ollvm16-rust-1.74.0"]).run()?;
        args.push("rustc".to_string());
        args.push("--release".to_string());
        args.push("--target".to_string());
        args.push(target.clone());
        args.push("-p".to_string());
        args.push(package.clone());
        if build_lib {
            args.push("--lib".to_string());
        } else {
            args.push("--bin".to_string());
            args.push(package.clone());
        }
        args.push("--".to_string());

        if config.ollvm.bcfobf {
            args.push("-Cllvm-args=-enable-bcfobf".to_string());
        }
        if config.ollvm.splitobf {
            args.push("-Cllvm-args=-enable-splitobf".to_string());
        }
        if config.ollvm.subobf {
            args.push("-Cllvm-args=-enable-subobf".to_string());
        }
        if config.ollvm.fco {
            args.push("-Cllvm-args=-enable-fco".to_string());
        }
        if config.ollvm.constenc {
            args.push("-Cllvm-args=-enable-constenc".to_string());
        }
        args.push("-Cdebuginfo=0".to_string());
        args.push("-Cstrip=symbols".to_string());
        args.push("-Cpanic=abort".to_string());
        args.push("-Copt-level=3".to_string());
    } else {
        if ollvm_flag.is_ok() {
            std::fs::remove_file(OLLVM_FLGAS)?;
        }
        let toolchain = config.toolchain.clone();
        let _ = cmd("rustup", ["default", &*toolchain]).run()?;
        if config.zigbuild {
            args.push("zigbuild".to_string());
        } else {
            args.push("build".to_string())
        }
        if profile.is_release() {
            args.push("--release".to_string());
        }
        args.push("--target".to_string());
        args.push(target.clone());
        args.push("-p".to_string());
        args.push(package.clone());
        if build_lib {
            args.push("--lib".to_string());
        } else {
            args.push("--bin".to_string());
            args.push(package.clone());
        }
    };

    let feature_string = features.filter(|f| !f.is_empty()).map(|f| f.join(","));

    if let Some(ref fs) = feature_string {
        args.push("--features".to_string());
        args.push(fs.clone());
    }

    // YY-Thunks
    let mut cargo_cmd = cmd("cargo", args);
    if target == "i686-pc-windows-msvc" {
        cargo_cmd = cargo_cmd.env("YY_THUNKS_TARGET_OS", "WinXP");
    }

    let result = cargo_cmd.stderr_to_stdout().stdout_capture().reader()?;

    use std::io::{BufRead, BufReader};
    let reader = BufReader::new(result);
    let mut has_error = false;

    for line in reader.lines() {
        match line {
            Ok(line) => {
                if line.contains("error:") {
                    log_error!("{}", line);
                    has_error = true;
                } else {
                    log_step!("{}", line);
                }
            }
            Err(_) => break,
        }
    }

    if has_error {
        return Err(anyhow::anyhow!(
            "Build failed - compilation errors detected"
        ));
    }
    let binary_path = compute_output_path(&package, target, target_platform, build_lib, profile);
    if profile.is_release() {
        let _ = strip_paths_from_binary(&binary_path, &binary_path, &[]);
    } else {
        log_step!("Skipping path stripping for dev build");
    }

    log_success!(
        "Build completed: {} ({} bytes)",
        binary_path,
        std::fs::metadata(&binary_path)
            .map(|m| m.len())
            .unwrap_or(0)
    );

    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum TargetPlatform {
    Windows,
    Linux,
    Mac,
}

fn detect_target_platform(target: &str) -> anyhow::Result<TargetPlatform> {
    let target_lower = target.to_lowercase();
    if target_lower.contains("windows") {
        Ok(TargetPlatform::Windows)
    } else if target_lower.contains("linux") {
        Ok(TargetPlatform::Linux)
    } else if target_lower.contains("darwin") || target_lower.contains("apple") {
        Ok(TargetPlatform::Mac)
    } else {
        anyhow::bail!("Unsupported target triple: {}", target);
    }
}

fn normalize_build_kind(
    payload_type: &PayloadType,
    requested_lib: bool,
    platform: TargetPlatform,
) -> anyhow::Result<bool> {
    let requires_lib = matches!(
        payload_type,
        PayloadType::MODULES | PayloadType::THIRD | PayloadType::PROXYDLL
    );
    let allows_bin = matches!(
        payload_type,
        PayloadType::MALEFIC | PayloadType::PRELUDE | PayloadType::PULSE
    );
    let allows_lib = matches!(
        payload_type,
        PayloadType::MALEFIC
            | PayloadType::MODULES
            | PayloadType::THIRD
            | PayloadType::PROXYDLL
            | PayloadType::PULSE
    );

    let build_lib = requires_lib || requested_lib;

    if build_lib && !allows_lib {
        anyhow::bail!(
            "{} does not support building as a shared library",
            payload_type
        );
    }
    if !build_lib && !allows_bin {
        anyhow::bail!(
            "{} currently only supports building as a shared library",
            payload_type
        );
    }

    // Platform compatibility gate
    match payload_type {
        PayloadType::PULSE | PayloadType::MODULES | PayloadType::THIRD | PayloadType::PROXYDLL => {
            if !matches!(platform, TargetPlatform::Windows) {
                anyhow::bail!("{} currently only supports Windows targets", payload_type);
            }
        }
        _ => {}
    }

    Ok(build_lib)
}

fn compute_output_path(
    package: &str,
    target: &str,
    platform: TargetPlatform,
    build_lib: bool,
    profile: BuildProfile,
) -> String {
    let (prefix, ext) = if build_lib {
        match platform {
            TargetPlatform::Windows => ("", "dll"),
            TargetPlatform::Linux => ("lib", "so"),
            TargetPlatform::Mac => ("lib", "dylib"),
        }
    } else {
        match platform {
            TargetPlatform::Windows => ("", "exe"),
            _ => ("", ""),
        }
    };

    // lib outputs use underscores (Rust convention), bin outputs keep hyphens
    let base = if build_lib {
        package.replace('-', "_")
    } else {
        package.to_string()
    };

    let mut filename = String::new();
    if !prefix.is_empty() {
        filename.push_str(prefix);
    }
    filename.push_str(&base);
    if !ext.is_empty() {
        filename.push('.');
        filename.push_str(ext);
    }
    format!("target/{}/{}/{}", target, profile.output_dir(), filename)
}

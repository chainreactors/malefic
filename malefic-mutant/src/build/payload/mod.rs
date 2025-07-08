#![allow(non_camel_case_types)]
use crate::{cmd::PayloadType, log_error, log_step, BuildConfig};
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

pub fn build_payload(
    config: &BuildConfig,
    payload_type: &PayloadType,
    target: &String,
    features: Option<&Vec<String>>,
) -> anyhow::Result<()> {
    let mut args = Vec::new();
    let package = match payload_type {
        PayloadType::THIRD => "malefic-3rd".to_string(),
        _ => payload_type.to_string(),
    };

    let ollvm_flag = std::fs::File::open(OLLVM_FLGAS);
    if config.ollvm.enable && OllvmAllow::from_str(&target).is_ok() {
        if ollvm_flag.is_err() {
            std::fs::File::create(OLLVM_FLGAS)?;
        }
        let _ = cmd("rustup", ["default", "ollvm16-rust-1.74.0"]).run()?;
        args.push("rustc");
        let build_type = match payload_type {
            PayloadType::MODULES => "--lib",
            _ => "--bin",
        };
        args.extend_from_slice(&[
            "--release",
            "--target",
            &target,
            "-p",
            &package,
            build_type,
            &package,
            "--",
        ]);

        if config.ollvm.bcfobf {
            args.push("-Cllvm-args=-enable-bcfobf");
        }
        if config.ollvm.splitobf {
            args.push("-Cllvm-args=-enable-splitobf");
        }
        if config.ollvm.subobf {
            args.push("-Cllvm-args=-enable-subobf");
        }
        if config.ollvm.fco {
            args.push("-Cllvm-args=-enable-fco");
        }
        if config.ollvm.constenc {
            args.push("-Cllvm-args=-enable-constenc");
        }
        args.push("-Cdebuginfo=0 -Cstrip=symbols -Cpanic=abort -Copt-level=3");

        if let Some(feats) = features {
            if !feats.is_empty() {
                args.push("--features");
                let feature_string = feats.join(",");
                let leaked: &'static str = Box::leak(feature_string.into_boxed_str());
                args.push(leaked);
            }
        }
    } else {
        if ollvm_flag.is_ok() {
            std::fs::remove_file(OLLVM_FLGAS)?;
        }
        let _ = cmd("rustup", ["default", "nightly-2023-09-18"]).run()?;
        if config.zigbuild {
            args.push("zigbuild");
        } else {
            args.push("build")
        }
        args.extend_from_slice(&["--release", "--target", &target, "-p", &package]);

        if let Some(feats) = features {
            if !feats.is_empty() {
                args.push("--features");
                let feature_string = feats.join(",");
                let leaked: &'static str = Box::leak(feature_string.into_boxed_str());
                args.push(leaked);
            }
        }
    };

    let result = cmd("cargo", args)
        .stderr_to_stdout()
        .stdout_capture()
        .reader()?;

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

    Ok(())
}

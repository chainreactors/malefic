#![allow(non_camel_case_types)]
use crate::{cmd::PayloadType, log_error, log_step, log_success, BuildConfig};
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
    target: &String
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
        args.push("-Cdebuginfo=0");
        args.push("-Cstrip=symbols");
        args.push("-Cpanic=abort");
        args.push("-Copt-level=3");
    } else {
        if ollvm_flag.is_ok() {
            std::fs::remove_file(OLLVM_FLGAS)?;
        }
        let toolchain = config.toolchain.clone();
        let _ = cmd("rustup", ["default", &*toolchain]).run()?;
        if config.zigbuild {
            args.push("zigbuild");
        } else {
            args.push("build")
        }
        args.extend_from_slice(&["--release", "--target", &target, "-p", &package]);
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
    // 根据package的不同输出
    let binary_path = match payload_type {
        PayloadType::THIRD => {
            if target.contains("windows") {
                format!("target/{}/release/malefic_3rd.dll", target)
            } else {
                format!("target/{}/release/libmalefic_3rd.rlib", target)
            }
        },
        PayloadType::MODULES => {
            if target.contains("windows") {
                format!("target/{}/release/malefic_modules.dll", target)
            } else {
                format!("target/{}/release/libmalefic_modules.rlib", target)
            }
        },
        _ => {
            if target.contains("windows") {
                format!("target/{}/release/{}.exe", target, package)
            } else {
                format!("target/{}/release/{}", target, package)
            }
        }
    };

    log_success!("Build completed: {}", binary_path);

    Ok(())
}

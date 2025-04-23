#![allow(dead_code)]
#![allow(unused_imports)]
use std::{env, path::PathBuf};

struct LibraryConfig {
    name: String,
    supported_os: Vec<&'static str>,
    supported_arch: Vec<&'static str>,
    lib_name_format: String,
    windows_deps: Vec<&'static str>,
}

impl LibraryConfig {
    fn new(
        name: &str,
        supported_os: Vec<&'static str>,
        supported_arch: Vec<&'static str>,
        lib_name_format: &str,
        windows_deps: Vec<&'static str>,
    ) -> Self {
        Self {
            name: name.to_string(),
            supported_os,
            supported_arch,
            lib_name_format: lib_name_format.to_string(),
            windows_deps,
        }
    }

    fn check_platform_support(&self, target_os: &str, target_arch: &str) -> Result<(), String> {
        if !self.supported_arch.contains(&target_arch) {
            return Err(format!(
                "{} only supports architectures: {}",
                self.name,
                self.supported_arch.join(", ")
            ));
        }

        if !self.supported_os.contains(&target_os) {
            return Err(format!(
                "{} only supports operating systems: {}",
                self.name,
                self.supported_os.join(", ")
            ));
        }

        Ok(())
    }

    fn get_lib_path(
        &self,
        resources_path: &PathBuf,
        target_os: &str,
        target_arch: &str,
    ) -> PathBuf {
        let lib_name = self
            .lib_name_format
            .replace("{os}", target_os)
            .replace("{arch}", target_arch);
        resources_path.join(&lib_name)
    }

    fn link_library(
        &self,
        resources_path: &PathBuf,
        target_os: &str,
        target_arch: &str,
    ) -> Result<(), String> {
        self.check_platform_support(target_os, target_arch)?;

        let lib_path = self.get_lib_path(resources_path, target_os, target_arch);
        if !lib_path.exists() {
            return Err(format!(
                "Required library file not found: {}\n{} only supports {} on {}",
                lib_path.display(),
                self.name,
                self.supported_os.join(", "),
                self.supported_arch.join(", ")
            ));
        }

        // 设置库搜索路径
        println!(
            "cargo:rustc-link-search=native={}",
            resources_path.display()
        );

        // 链接主库
        let formatted_name = self
            .lib_name_format
            .replace("{os}", target_os)
            .replace("{arch}", target_arch);

        let lib_name = formatted_name
            .strip_prefix("lib")
            .and_then(|s| s.strip_suffix(".a"))
            .unwrap_or(&formatted_name);

        println!("cargo:rustc-link-lib=static={}", lib_name);

        // Windows 特定依赖
        if target_os == "windows" {
            for dep in &self.windows_deps {
                println!("cargo:rustc-link-lib=dylib={}", dep);
            }
        }

        // 设置重新运行条件
        println!("cargo:rerun-if-changed={}", lib_path.display());

        Ok(())
    }
}

fn main() {
    #[cfg(feature = "rem_static")]
    {
        let resources_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("resources");

        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
        let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

        let rem_config = LibraryConfig::new(
            "REM",
            vec!["windows", "linux"],
            vec!["amd64"],
            "librem_community_{os}_{arch}.a",
            vec!["ws2_32", "userenv"],
        );

        if let Err(e) = rem_config.link_library(&resources_path, &target_os, &target_arch) {
            panic!("{}", e);
        }
    }

    #[cfg(feature = "prebuild")]
    {
        if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
            let (prefix, suffix, destination) =
                match env::var("CARGO_CFG_TARGET_ENV").unwrap().as_str() {
                    "msvc" => (
                        "malefic-win-kit-community-msvc",
                        ".lib",
                        "malefic_win_kit.lib",
                    ),
                    _ => (
                        "libmalefic-win-kit-community-gnu",
                        ".a",
                        "libmalefic_win_kit.a",
                    ),
                };

            let arch = if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "x86" {
                "x32"
            } else {
                "x64"
            };

            let lib_name = format!("{prefix}-{arch}{suffix}");
            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
            let source_path = env::current_dir()
                .unwrap()
                .parent()
                .unwrap()
                .join("resources")
                .join(&lib_name);

            if !source_path.exists() {
                panic!("Source file not found: {}", source_path.display());
            }

            let destination_path = out_dir.join(destination);

            std::fs::copy(&source_path, &destination_path)
                .expect(&format!("Failed to copy file {}", source_path.display()));

            println!("cargo:rustc-link-search=native={}", out_dir.display());
            println!("cargo:rustc-link-lib=static=malefic_win_kit");
        }
    }
}

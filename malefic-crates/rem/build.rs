use std::{env, path::PathBuf};

fn main() {
    let features: Vec<String> = env::vars()
        .filter(|(k, _)| k.starts_with("CARGO_FEATURE_"))
        .map(|(k, _)| k)
        .collect();

    if features.iter().any(|f| f == "CARGO_FEATURE_REM_DYNAMIC") {
        // Dynamic mode: no static libraries needed.
        // DLL is loaded at runtime via LoadLibraryA.
    }

    if features.iter().any(|f| f == "CARGO_FEATURE_REM_STATIC") {
        let resources_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("resources");

        let target_os = match env::var("CARGO_CFG_TARGET_OS").unwrap().as_str() {
            "macos" => "darwin".to_string(),
            other => other.to_string(),
        };
        let target_arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            _ => panic!("Unsupported architecture"),
        };

        let lib_name = format!("librem_community_{}_{}.a", target_os, target_arch);
        let lib_path = resources_path.join(&lib_name);

        if !lib_path.exists() {
            panic!("Required library file not found: {}", lib_path.display());
        }

        println!(
            "cargo:rustc-link-search=native={}",
            resources_path.display()
        );

        let link_name = lib_name
            .strip_prefix("lib")
            .and_then(|s| s.strip_suffix(".a"))
            .unwrap_or(&lib_name);
        println!("cargo:rustc-link-lib=static={}", link_name);

        if target_os == "windows" {
            println!("cargo:rustc-link-lib=dylib=ws2_32");
            println!("cargo:rustc-link-lib=dylib=userenv");
        }

        println!("cargo:rerun-if-changed={}", lib_path.display());
    }
}

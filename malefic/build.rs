use std::{env};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../resources/malefic.rc");
    println!("cargo:rerun-if-changed=../resources/app.manifest");
    println!("test build!");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_else(|_| "unknown".to_string());
    
    println!("Detected target OS: {}", target_os);
    println!("Detected target ENV: {}", target_env);

    if target_os.to_lowercase() == "windows" {
        use embed_resource::CompilationResult;
        let current_dir = std::env::current_dir().expect("Failed to get current directory");
        let rc_path = current_dir.join("../resources/malefic.rc");
        println!("rc_path: {}", rc_path.display());

        match embed_resource::compile(rc_path,embed_resource::NONE) {
            CompilationResult::Ok =>
                println!("cargo:warning=embed_resource compiled successfully"),
            CompilationResult::Failed(e) =>
                panic!("embed_resource failed: {}", e),
            CompilationResult::NotAttempted(reason) =>
                panic!("RC compiler not found: {}", reason),
            CompilationResult::NotWindows =>
                println!("cargo:warning=Not on Windows platform"),
        }
    }
}

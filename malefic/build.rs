use std::path::Path;
use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../resources/malefic.rc");
    println!("cargo:rerun-if-changed=../resources/app.manifest");
    println!("test build!");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_else(|_| "unknown".to_string());
    
    println!("Detected target OS: {}", target_os);
    println!("Detected target ENV: {}", target_env);

    #[cfg(target_os = "windows")]
    if target_os == "windows"{
        let current_dir = env::current_dir().expect("Failed to get current directory");
        let rc_path = Path::new("../resources/malefic.rc");
        let absolute_rc_path = fs::canonicalize(current_dir.join(rc_path))
            .expect("Failed to canonicalize the resource file path");
        println!("rc_path: {}", absolute_rc_path.to_str().unwrap());
    
        let _ = embed_resource::compile(absolute_rc_path, embed_resource::NONE);
    }
}

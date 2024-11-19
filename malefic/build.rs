use std::{env, fs};
use std::path::Path;
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../resources/malefic.rc");
    println!("test build!");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_else(|_| "unknown".to_string());

    println!("Detected target OS: {}", target_os);
    println!("Detected target ENV: {}", target_env);
    #[cfg(all(target_os = "windows", any(target_env = "gnu", target_env = "msvc")))]
    {
        let mut rc = winres::WindowsResource::new();
        let current_dir = env::current_dir().expect("Failed to get current directory");
        let rc_path = Path::new("../resources/malefic.rc");
        let absolute_rc_path = fs::canonicalize(current_dir.join(rc_path))
            .expect("Failed to canonicalize the resource file path");
        println!("rc_path: {}", absolute_rc_path.to_str().unwrap());
        let mut absolute_rc_str = absolute_rc_path.to_str().expect("Path is not valid UTF-8");
        if absolute_rc_str.starts_with(r"\\?\") {
            absolute_rc_str = &absolute_rc_str[4..];
        }
        println!("absolute_rc_str: {}", absolute_rc_str);
        rc.set_resource_file(absolute_rc_str);

        if let Err(err) = rc.compile() {
            eprintln!("Warning: Failed to compile resource file: {}", err);
        }
    }
}

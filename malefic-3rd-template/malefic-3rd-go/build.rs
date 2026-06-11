use std::env;
use std::path::PathBuf;
use std::process::Command;

fn build_go(go_src_dir: &PathBuf, archive_path: &PathBuf) {
    // Standard Go c-archive: fully self-contained static library
    let status = Command::new("go")
        .current_dir(go_src_dir)
        .env("CGO_ENABLED", "1")
        .arg("build")
        .arg("-buildmode=c-archive")
        .arg("-ldflags=-s -w")
        .arg("-trimpath")
        .arg("-gcflags=-B")
        .arg("-o")
        .arg(archive_path)
        .arg(".")
        .status()
        .expect("Failed to execute `go build`. Is Go installed and in PATH?");

    if !status.success() {
        panic!("go build -buildmode=c-archive failed");
    }
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let go_module_dir = if cfg!(feature = "go_hackbrowser") {
        "hackbrowser"
    } else {
        "example"
    };
    let go_src_dir = manifest_dir.join("src").join("go").join(go_module_dir);
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let lib_name = "malefic_go";
    let archive_path = out_dir.join(format!("lib{}.a", lib_name));

    build_go(&go_src_dir, &archive_path);

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static={}", lib_name);

    // Go runtime needs platform libs
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match target_os.as_str() {
        "windows" => {
            for lib in &["ws2_32", "winmm", "ntdll", "userenv", "bcrypt"] {
                println!("cargo:rustc-link-lib=dylib={}", lib);
            }
        }
        "linux" => {
            for lib in &["pthread", "dl", "m"] {
                println!("cargo:rustc-link-lib=dylib={}", lib);
            }
        }
        "macos" => {
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            println!("cargo:rustc-link-lib=framework=Security");
            println!("cargo:rustc-link-lib=dylib=pthread");
        }
        _ => {}
    }

    println!("cargo:rerun-if-changed={}", go_src_dir.display());
}

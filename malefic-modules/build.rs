use std::env;
use std::path::PathBuf;

fn main() {
    #[cfg(feature = "community")]
    {
        loop {
            if std::env::var("CARGO_CFG_TARGET_OS").unwrap() != "windows" {
                break;
            }
            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
            if std::env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "x86_64" {
                std::fs::copy("../resources/libmalefic_win_kit.a", out_dir.join("libmalefic_win_kit.a")).unwrap();
            } else if std::env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "x86" {
                std::fs::copy("../resources/libmalefic_win_kit32.a", out_dir.join("libmalefic_win_kit.a")).unwrap();

            } else {
                break;
            }
            println!("cargo:rustc-link-search=native={}", out_dir.display());
            println!("cargo:rustc-link-lib=static={}", "malefic_win_kit");
            break;
        }

    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=path/to/Cargo.lock");
}

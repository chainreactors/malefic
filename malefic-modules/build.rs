use std::env;
use std::path::PathBuf;

fn main() {
    #[cfg(feature = "community")]
    {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR environment variable not set");
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        #[cfg(target_arch="x86_64")]
        std::fs::copy("../resources/libmalefic_win_kit.a", out_dir.join("libmalefic_win_kit.a")).unwrap();
        #[cfg(target_arch="x86")]
        std::fs::copy("../resources/libmalefic_win_kit32.a", out_dir.join("libmalefic_win_kit.a")).unwrap();
        println!("cargo:rustc-link-search=native={}", out_dir.display());
        println!("cargo:rustc-link-lib=static={}", "malefic_win_kit");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=path/to/Cargo.lock");
}

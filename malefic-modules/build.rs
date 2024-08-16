use std::env;
use std::path::PathBuf;

fn main() {
    #[cfg(feature = "community")]
    {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR environment variable not set");
        let lib_path = PathBuf::from(manifest_dir).join("../resources/");
        println!("lib path is {:#?}", lib_path.display());
        println!("cargo:rustc-link-search=native={}", lib_path.display());
        println!("cargo:rustc-link-lib=static=malefic_win_kit");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=path/to/Cargo.lock");
}

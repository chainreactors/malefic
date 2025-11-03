use std::env;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let target = env::var("TARGET").unwrap_or_default();

    // Handle .def file linking
    let def_path = Path::new(&manifest_dir).join("proxy.def");
    if def_path.exists() {
        // Use correct syntax based on toolchain
        if target.contains("msvc") {
            // MSVC linker syntax
            println!("cargo:rustc-link-arg=/DEF:{}", def_path.display());
        } else if target.contains("gnu") {
            // MinGW/GNU linker syntax - pass DEF file directly as object
            println!("cargo:rustc-cdylib-link-arg={}", def_path.display());
        }
        println!("cargo:rerun-if-changed=proxy.def");
    }

    // Rerun if core files change
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/payload.rs");
}
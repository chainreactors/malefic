use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let nim_src_dir = manifest_dir.join("src").join("nim");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let nanopb_dir = nim_src_dir.join("nanopb");
    let malefic_dir = nim_src_dir.join("malefic");

    // 1. Compile nanopb core + module.pb.c via cc crate
    cc::Build::new()
        .file(nanopb_dir.join("pb_encode.c"))
        .file(nanopb_dir.join("pb_decode.c"))
        .file(nanopb_dir.join("pb_common.c"))
        .file(malefic_dir.join("module.pb.c"))
        .include(&nanopb_dir)
        .include(&malefic_dir)
        .define("PB_FIELD_32BIT", None)
        .warnings(false)
        .compile("malefic_nim_nanopb");

    // 2. Compile Nim example module → static library
    let nim_source = nim_src_dir.join("example").join("example.nim");
    let nim_out = out_dir.join("libmalefic_nim.a");

    let nim_cache = out_dir.join("nimcache");
    std::fs::create_dir_all(&nim_cache).ok();

    let status = Command::new("nim")
        .args([
            "c",
            "--app:staticlib",
            "--mm:arc",
            "--noMain:on",
        ])
        .arg(format!("--nimcache:{}", nim_cache.display()))
        .arg(format!("--passC:-I{}", nanopb_dir.display()))
        .arg(format!("--passC:-I{}", malefic_dir.display()))
        .arg("--passC:-DPB_FIELD_32BIT")
        .arg(format!("--out:{}", nim_out.display()))
        .arg(nim_source.to_str().unwrap())
        .status()
        .expect("Failed to run nim compiler. Is nim installed?");

    if !status.success() {
        panic!("Nim compilation failed");
    }

    // 3. Link both libraries
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=malefic_nim_nanopb");
    println!("cargo:rustc-link-lib=static=malefic_nim");

    println!("cargo:rerun-if-changed={}", nim_src_dir.display());
}

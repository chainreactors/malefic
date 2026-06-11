use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let zig_src_dir = manifest_dir.join("src").join("zig");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let nanopb_include = zig_src_dir.join("nanopb");
    let malefic_include = zig_src_dir.join("malefic");

    // 1. Compile nanopb core + module.pb.c via cc crate
    cc::Build::new()
        .file(zig_src_dir.join("nanopb").join("pb_encode.c"))
        .file(zig_src_dir.join("nanopb").join("pb_decode.c"))
        .file(zig_src_dir.join("nanopb").join("pb_common.c"))
        .file(zig_src_dir.join("malefic").join("module.pb.c"))
        .include(&nanopb_include)
        .include(&malefic_include)
        .define("PB_FIELD_32BIT", None)
        .warnings(false)
        .compile("malefic_zig_nanopb");

    // 2. Compile Zig example module → object file
    let zig_source = zig_src_dir.join("example").join("example.zig");
    let zig_obj = out_dir.join("example_zig.obj");

    let status = Command::new("zig")
        .args([
            "build-obj",
            "-O", "ReleaseSafe",
            "-lc",
            "-DPB_FIELD_32BIT",
        ])
        .arg(format!("-I{}", nanopb_include.display()))
        .arg(format!("-I{}", malefic_include.display()))
        .arg(format!("-femit-bin={}", zig_obj.display()))
        .arg(zig_source.to_str().unwrap())
        .status()
        .expect("Failed to run zig compiler. Is zig installed?");

    if !status.success() {
        panic!("Zig compilation failed");
    }

    // 3. Wrap zig object into a static library via cc crate
    //    This ensures symbols propagate correctly across crate boundaries.
    cc::Build::new()
        .object(&zig_obj)
        .compile("malefic_zig_example");

    println!("cargo:rerun-if-changed={}", zig_src_dir.display());
}

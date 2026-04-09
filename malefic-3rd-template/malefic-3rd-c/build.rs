use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let c_src_dir = manifest_dir.join("src").join("c");

    cc::Build::new()
        // nanopb core
        .file(c_src_dir.join("nanopb").join("pb_encode.c"))
        .file(c_src_dir.join("nanopb").join("pb_decode.c"))
        .file(c_src_dir.join("nanopb").join("pb_common.c"))
        // nanopb generated
        .file(c_src_dir.join("malefic").join("module.pb.c"))
        // module framework + example
        .file(c_src_dir.join("module.c"))
        .file(c_src_dir.join("example").join("example.c"))
        // include paths
        .include(c_src_dir.join("nanopb"))
        .include(c_src_dir.join("malefic"))
        .include(&c_src_dir)
        // Large messages (PsResponse, LsResponse, etc.) exceed 64kB
        .define("PB_FIELD_32BIT", None)
        .warnings(false)
        .compile("malefic_c");

    println!("cargo:rerun-if-changed={}", c_src_dir.display());
}

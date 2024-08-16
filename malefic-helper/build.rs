use std::env;
use std::path::PathBuf;
use lazy_static::lazy_static;

lazy_static! {
    static ref PROTO_GENE_PATH : &'static str = "src/protobuf";
    static ref PROTO_PARSE_FILE : &'static str = "../proto/implant/implantpb/implant.proto";
}

fn main() {
    #[cfg(feature = "community")]
    {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR environment variable not set");
        let lib_path = PathBuf::from(manifest_dir).join("../resources");
        println!("lib path is {:#?}", lib_path.display());
        println!("cargo:rustc-link-search=native={}", lib_path.display());
        println!("cargo:rustc-link-lib=static=malefic_win_kit");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=path/to/Cargo.lock");
    println!("test build!");

    let mut prost_config = prost_build::Config::new();

    prost_config.out_dir(PROTO_GENE_PATH.to_string());
    // prost_config.btree_map(&["."]);
    prost_config.compile_protos(
        &[PROTO_PARSE_FILE.to_string()],
        &["../proto/"]).unwrap();
}
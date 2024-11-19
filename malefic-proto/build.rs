
const PROTO_GENE_PATH: &str = "src/proto/";
const PROTO_IMPLANT_FILE: &str = "../proto/implant/implantpb/implant.proto";
const PROTO_MODULE_FILE: &str = "../proto/implant/implantpb/module.proto";

fn main() {
    // println!("cargo:rerun-if-changed=build.rs");
    // println!("cargo:rerun-if-changed=../proto/implant/implantpb/implant.proto");
    // println!("cargo:rerun-if-changed=../proto/implant/implantpb/module.proto");
    println!("test build!");
    let mut prost_config = prost_build::Config::new();
    #[cfg(feature = "enable_serde")]
    {
        prost_config.type_attribute(".", "#[derive(serde::Deserialize)]");
        prost_config.field_attribute(".modulepb", "#[serde(default)]");
    }

    #[cfg(all(not(debug_assertions), not(feature = "enable_serde")))]
    {
        prost_config.skip_debug(["."]);
    }
    

    prost_config.out_dir(PROTO_GENE_PATH.to_string());
    // prost_config.btree_map(&["."]);
    let _ = prost_config
        .compile_protos(&[PROTO_IMPLANT_FILE.to_string(), PROTO_MODULE_FILE.to_string()], &["../proto/"]);
}
const PROTO_GENE_PATH: &str = "src/proto/";
const PROTO_IMPLANT_FILE: &str = "../../proto/implant/implantpb/implant.proto";
const PROTO_MODULE_FILE: &str = "../../proto/implant/implantpb/module.proto";

fn main() {
    let mut prost_config = prost_build::Config::new();
    #[cfg(feature = "enable_serde")]
    {
        prost_config.type_attribute(".", "#[derive(serde::Deserialize)]");
        prost_config.field_attribute(".modulepb", "#[serde(default)]");
    }

    #[cfg(feature = "inplace_obf")]
    {
        prost_config.type_attribute(".", "#[derive(::malefic_gateway::Obfuscate)]");
    }

    #[cfg(all(not(debug_assertions), not(feature = "enable_serde")))]
    {
        prost_config.skip_debug(["."]);
        prost_config.skip_field_names(["."]);
    }

    prost_config.out_dir(PROTO_GENE_PATH.to_string());
    match prost_config.compile_protos(
        &[
            PROTO_IMPLANT_FILE.to_string(),
            PROTO_MODULE_FILE.to_string(),
        ],
        &["../../proto/"],
    ) {
        Ok(_) => {
            println!("Proto compilation successful!");
            // Post-process: remove #[serde(default)] from enum variants
            // prost's field_attribute applies to enum variants too, which serde rejects
            fix_serde_enum_variants(PROTO_GENE_PATH);
        }
        Err(e) => {
            eprintln!("Proto compilation error: {}", e);
            panic!("Failed to compile protos: {}", e);
        }
    }
}

/// Remove `#[serde(default)]` from enum variant positions in generated proto files.
///
/// prost's `field_attribute` applies to both struct fields and enum variants,
/// but `#[serde(default)]` is not valid on enum variants.
fn fix_serde_enum_variants(dir: &str) {
    use std::fs;
    for entry in fs::read_dir(dir).expect("failed to read proto output dir") {
        let entry = entry.expect("failed to read dir entry");
        let path = entry.path();
        if path.extension().map_or(true, |ext| ext != "rs") {
            continue;
        }
        let content = fs::read_to_string(&path).expect("failed to read generated file");
        let mut lines: Vec<&str> = content.lines().collect();
        let mut to_remove = Vec::new();

        // Find enum blocks and mark #[serde(default)] lines within them
        let mut in_enum = false;
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("pub enum ") {
                in_enum = true;
            } else if in_enum && trimmed == "}" {
                in_enum = false;
            } else if in_enum && trimmed == "#[serde(default)]" {
                to_remove.push(i);
            }
        }

        if !to_remove.is_empty() {
            for &i in to_remove.iter().rev() {
                lines.remove(i);
            }
            let fixed = lines.join("\n") + "\n";
            fs::write(&path, fixed).expect("failed to write fixed file");
            println!("Fixed serde enum variants in {:?}", path);
        }
    }
}

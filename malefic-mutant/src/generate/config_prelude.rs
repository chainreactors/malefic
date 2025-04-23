use crate::generate::config_modules::update_module_toml;
use crate::RESOURCES_DIR;
use crate::{log_info, log_success};
use base64::{self, prelude::BASE64_STANDARD, Engine};
use hex;
use malefic_proto::compress::compress;
use malefic_proto::crypto::new_cryptor;
use malefic_proto::encode;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::{Spite, Spites};
use serde_yaml::value::Tag;
use serde_yaml::{from_str, Number, Value};
use std::fs;
use std::io::Write;
use std::path::Path;

fn process_tags(value: &mut Value, path: &str) {
    match value {
        Value::Mapping(map) => {
            for (k, v) in map.iter_mut() {
                let key = k.as_str().unwrap_or("unknown");
                process_tags(v, &format!("{} > {}", path, key));
            }
        }
        Value::Sequence(seq) => {
            for (i, v) in seq.iter_mut().enumerate() {
                process_tags(v, &format!("{}[{}]", path, i));
            }
        }
        Value::Tagged(tagged) => {
            if tagged.tag == Tag::new("!File") {
                if let Value::String(file_path) = &tagged.value {
                    let base_filepath = Path::new(RESOURCES_DIR);
                    let resource_filepath = base_filepath.join(file_path);
                    let file_content = fs::read(resource_filepath.clone()).unwrap_or_else(|err| {
                        panic!(
                            "Failed to read file '{:?}': {} at {}",
                            resource_filepath, err, path
                        );
                    });
                    *value = Value::Sequence(
                        file_content
                            .into_iter()
                            .map(|byte| Value::Number(Number::from(byte as i64)))
                            .collect(),
                    );
                }
            } else if tagged.tag == Tag::new("!Base64") {
                if let Value::String(encoded_str) = &tagged.value {
                    let decoded_bytes = BASE64_STANDARD.decode(encoded_str).unwrap_or_else(|err| {
                        panic!(
                            "Failed to decode base64 string '{}': {} at {}",
                            encoded_str, err, path
                        );
                    });
                    *value = Value::Sequence(
                        decoded_bytes
                            .into_iter()
                            .map(|byte| Value::Number(Number::from(byte as i64)))
                            .collect(),
                    );
                }
            } else if tagged.tag == Tag::new("!Hex") {
                if let Value::String(hex_str) = &tagged.value {
                    let decoded_bytes = hex::decode(hex_str).unwrap_or_else(|err| {
                        panic!(
                            "Failed to decode hex string '{}': {} at {}",
                            hex_str, err, path
                        );
                    });
                    *value = Value::Sequence(
                        decoded_bytes
                            .into_iter()
                            .map(|byte| Value::Number(Number::from(byte as i64)))
                            .collect(),
                    );
                }
            } else {
                process_tags(&mut tagged.value, path);
            }
        }
        _ => {}
    }
}

fn parse_yaml_with_tag<T>(yaml_str: &str) -> T
where
    T: serde::de::DeserializeOwned,
{
    let mut yaml_value: Value = from_str(yaml_str).expect("Failed to parse YAML");
    process_tags(&mut yaml_value, "root");
    serde_yaml::from_value(yaml_value).expect("Failed to deserialize into target type")
}

#[derive(serde::Deserialize, Debug)]
struct SpiteWrapper {
    #[serde(default)]
    name: String,
    #[serde(default)]
    task_id: u32,
    #[serde(default)]
    r#async: bool,
    #[serde(default)]
    timeout: u64,
    #[serde(default)]
    error: u32,
    #[serde(default)]
    status: Option<malefic_proto::proto::implantpb::Status>,
    body: Option<Body>,
}

pub fn parse_yaml(yaml_str: &str) -> Vec<Spite> {
    let spites_wrappers: Vec<SpiteWrapper> = parse_yaml_with_tag(yaml_str);

    let mut spites = Vec::new();
    for wrapper in spites_wrappers {
        if let Some(body) = wrapper.body {
            spites.push(Spite {
                name: wrapper.name,
                task_id: wrapper.task_id,
                r#async: wrapper.r#async,
                timeout: wrapper.timeout,
                error: wrapper.error,
                status: wrapper.status,
                body: Some(body),
            });
        }
    }
    spites
}

pub fn update_prelude_spites(
    spites: Vec<Spite>,
    resources: &str,
    key: &str,
    output: &str,
) -> anyhow::Result<()> {
    let base_filepath = Path::new(resources);

    let mut modules = Vec::new();
    for spite in &spites {
        if !modules.contains(&spite.name) {
            modules.push(spite.name.clone());
        }
    }
    log_info!("Detected modules from prelude: {:?}", modules);
    update_module_toml(&modules);

    let data = encode(Spites { spites })?;
    let compressed = compress(&data)?;
    let iv = key.as_bytes().to_vec().iter().rev().cloned().collect();
    let mut cryptor = new_cryptor(key.as_bytes().to_vec(), iv);
    let encrypted = cryptor.encrypt(compressed)?;
    let spite_path = base_filepath.join(output);
    let mut file = std::fs::File::create(spite_path.clone())?;
    file.write_all(&encrypted)?;
    log_success!("Data successfully written to {:?}", spite_path);
    Ok(())
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_marshal_spite() {
//         let spite = Spite {
//             name: "bof".to_string(),
//             task_id: 1,
//             r#async: false,
//             timeout: 1000,
//             error: 0,
//             status: None,
//             body: Some(Body::ExecuteBinary(malefic_proto::proto::modulepb::ExecuteBinary {
//                 name: "systeminfo".to_string(),
//                 bin: vec![],
//                 param: Default::default(),
//                 r#type: "".to_string(),
//                 process_name: "".to_string(),
//                 args: vec![],
//                 entry_point: "".to_string(),
//                 output: false,
//                 arch: 0,
//                 timeout: 0,
//                 sacrifice: None,
//             })),
//         };

//         let spite_str = serde_yaml::to_string(&spite).expect("Failed to serialize Spite");
//         println!("{}", spite_str.as_str())
//     }

//     #[test]
//     fn test_parse_yaml() {
//         let current_dir = std::env::current_dir().expect("Failed to get current directory");
//         println!("Current working directory: {}", current_dir.display());

//         let yaml_str = r#"
// -
//   name: bof
//   body: !ExecuteBinary
//     name: systeminfo
// "#;

//         // 解析 YAML，并生成 Vec<Spite>
//         let spites = parse_yaml(yaml_str);

//         // 打印结果，检查是否正确生成并自动生成省略的字段
//         for spite in &spites {
//             println!("{:?}", spite);
//         }

//         // 清理测试文件
//     }
// }

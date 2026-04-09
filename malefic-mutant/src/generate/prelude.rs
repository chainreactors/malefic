use crate::{log_info, log_success, RESOURCES_DIR};

use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine};
use malefic_crypto::compress::compress;
use malefic_crypto::crypto::new_cryptor;
use malefic_proto::encode;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::{Spite, Spites};
use serde_yaml::value::Tag;
use serde_yaml::{from_str, Number, Value};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Convert bytes to YAML sequence of numbers
fn bytes_to_yaml_sequence(bytes: Vec<u8>) -> Value {
    Value::Sequence(
        bytes
            .into_iter()
            .map(|byte| Value::Number(Number::from(byte as i64)))
            .collect(),
    )
}

/// Process custom YAML tags (!File, !Base64, !Hex) recursively
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
        Value::Tagged(tagged) => match &tagged.tag {
            tag if *tag == Tag::new("!File") => {
                if let Value::String(file_path) = &tagged.value {
                    let resource_filepath = Path::new(RESOURCES_DIR).join(file_path);
                    let file_content = fs::read(&resource_filepath).unwrap_or_else(|err| {
                        panic!(
                            "Failed to read file '{:?}': {} at {}",
                            resource_filepath, err, path
                        );
                    });
                    *value = bytes_to_yaml_sequence(file_content);
                }
            }
            tag if *tag == Tag::new("!Base64") => {
                if let Value::String(encoded_str) = &tagged.value {
                    let decoded_bytes = BASE64_STANDARD.decode(encoded_str).unwrap_or_else(|err| {
                        panic!(
                            "Failed to decode base64 string '{}': {} at {}",
                            encoded_str, err, path
                        );
                    });
                    *value = bytes_to_yaml_sequence(decoded_bytes);
                }
            }
            tag if *tag == Tag::new("!Hex") => {
                if let Value::String(hex_str) = &tagged.value {
                    let decoded_bytes = hex::decode(hex_str).unwrap_or_else(|err| {
                        panic!(
                            "Failed to decode hex string '{}': {} at {}",
                            hex_str, err, path
                        );
                    });
                    *value = bytes_to_yaml_sequence(decoded_bytes);
                }
            }
            _ => {
                process_tags(&mut tagged.value, path);
            }
        },
        _ => {}
    }
}

/// Parse YAML with custom tag processing
fn parse_yaml_with_tag<T>(yaml_str: &str) -> T
where
    T: serde::de::DeserializeOwned,
{
    let mut yaml_value: Value = from_str(yaml_str).expect("Failed to parse YAML");
    process_tags(&mut yaml_value, "root");
    serde_yaml::from_value(yaml_value).expect("Failed to deserialize into target type")
}

/// Wrapper for Spite with additional metadata
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
    /// Flag to indicate if this is a 3rd party module
    #[serde(default)]
    third: bool,
    /// Explicit feature dependency (overrides name for Cargo.toml features)
    /// Can be a single string or array of strings
    #[serde(default)]
    depend_on: Option<DependOn>,
    body: Option<Body>,
}

/// Support both single string and array of strings for depend_on
#[derive(serde::Deserialize, Debug, Clone)]
#[serde(untagged)]
enum DependOn {
    Single(String),
    Multiple(Vec<String>),
}

impl DependOn {
    fn into_vec(self) -> Vec<String> {
        match self {
            DependOn::Single(s) => vec![s],
            DependOn::Multiple(v) => v,
        }
    }
}

/// Parsed spites with module classification
pub struct ParsedSpites {
    pub spites: Vec<Spite>,
    pub regular_modules: Vec<String>,
    pub third_modules: Vec<String>,
}

/// Parse YAML configuration and classify modules
pub fn parse_yaml(yaml_str: &str) -> ParsedSpites {
    let spites_wrappers: Vec<SpiteWrapper> = parse_yaml_with_tag(yaml_str);

    let mut spites = Vec::new();
    let mut regular_modules = Vec::new();
    let mut third_modules = Vec::new();

    for wrapper in spites_wrappers {
        if let Some(body) = wrapper.body {
            spites.push(Spite {
                name: wrapper.name.clone(),
                task_id: wrapper.task_id,
                r#async: wrapper.r#async,
                timeout: wrapper.timeout,
                error: wrapper.error,
                status: wrapper.status,
                body: Some(body),
            });

            // Get features: use depend_on if specified, otherwise fall back to name
            let features = wrapper
                .depend_on
                .map(|d| d.into_vec())
                .unwrap_or_else(|| vec![wrapper.name]);

            // Classify and collect module features
            let module_list = if wrapper.third {
                &mut third_modules
            } else {
                &mut regular_modules
            };

            for feature in features {
                if !module_list.contains(&feature) {
                    module_list.push(feature);
                }
            }
        }
    }

    ParsedSpites {
        spites,
        regular_modules,
        third_modules,
    }
}

/// Update prelude spites and corresponding Cargo.toml files
pub fn update_prelude_spites(
    parsed: ParsedSpites,
    resources: &str,
    key: &str,
    output: &str,
) -> Result<()> {
    let base_filepath = Path::new(resources);

    log_info!(
        "Detected regular modules from prelude: {:?}",
        parsed.regular_modules
    );
    log_info!(
        "Detected 3rd modules from prelude: {:?}",
        parsed.third_modules
    );

    // Encode, compress, and encrypt spites
    let data = encode(Spites {
        spites: parsed.spites,
    })?;
    let compressed = compress(&data)?;
    let iv: Vec<u8> = key.as_bytes().iter().rev().copied().collect();
    let mut cryptor = new_cryptor(key.as_bytes().to_vec(), iv);
    let encrypted = cryptor.encrypt(compressed)?;

    // Write encrypted data to file
    let spite_path = base_filepath.join(output);
    let mut file = fs::File::create(&spite_path)?;
    file.write_all(&encrypted)?;

    log_success!("Data successfully written to {:?}", spite_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_yaml;

    #[test]
    fn parse_yaml_collects_regular_and_third_party_features() {
        let yaml = r#"
- name: pwd
  body: !Request
    name: pwd
- name: bof
  depend_on:
    - execute_bof
    - execute_local
  body: !Request
    name: bof
- name: pty
  third: true
  depend_on: pty
  body: !PtyRequest
    command: "cmd.exe"
"#;

        let parsed = parse_yaml(yaml);

        assert_eq!(
            parsed.regular_modules,
            vec![
                "pwd".to_string(),
                "execute_bof".to_string(),
                "execute_local".to_string()
            ]
        );
        assert_eq!(parsed.third_modules, vec!["pty".to_string()]);
        assert_eq!(parsed.spites.len(), 3);
    }

    #[test]
    fn depend_on_overrides_name_and_deduplicates_features() {
        let yaml = r#"
- name: execute
  depend_on:
    - exec
    - exec
  body: !Request
    name: execute
"#;

        let parsed = parse_yaml(yaml);

        assert_eq!(parsed.regular_modules, vec!["exec".to_string()]);
        assert!(parsed.third_modules.is_empty());
    }
}

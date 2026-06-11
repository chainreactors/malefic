use anyhow::Context;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use toml_edit::DocumentMut;

use super::cargo_features;
use crate::{log_debug, log_info, log_warning, CONFIG_SCHEMA};

// ── Feature Scanner ────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CrateFeatures {
    name: String,
    features: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
struct FeatureRegistry {
    crates: HashMap<String, CrateFeatures>,
}

impl FeatureRegistry {
    fn scan_workspace(workspace_root: &Path) -> anyhow::Result<Self> {
        let root_content = fs::read_to_string(workspace_root.join("Cargo.toml"))
            .context("Failed to read workspace Cargo.toml")?;
        let root_doc: DocumentMut = root_content
            .parse()
            .context("Failed to parse workspace Cargo.toml")?;

        let members = root_doc
            .get("workspace")
            .and_then(|w| w.get("members"))
            .and_then(|m| m.as_array())
            .context("No workspace.members found")?;

        let mut crates = HashMap::new();
        for member in members.iter() {
            let member_path = member
                .as_str()
                .context("workspace member is not a string")?;
            let crate_toml_path = workspace_root.join(member_path).join("Cargo.toml");
            if !crate_toml_path.exists() {
                continue;
            }
            match Self::parse_crate_features(&crate_toml_path) {
                Ok(cf) => {
                    crates.insert(cf.name.clone(), cf);
                }
                Err(e) => {
                    log_warning!("Failed to parse features for {}: {}", member_path, e);
                }
            }
        }
        log_info!("Scanned {} workspace crates", crates.len());
        Ok(FeatureRegistry { crates })
    }

    fn parse_crate_features(toml_path: &Path) -> anyhow::Result<CrateFeatures> {
        let content = fs::read_to_string(toml_path)
            .with_context(|| format!("Failed to read {}", toml_path.display()))?;
        let doc: DocumentMut = content
            .parse()
            .with_context(|| format!("Failed to parse {}", toml_path.display()))?;

        let name = doc
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();

        let mut features = HashMap::new();
        if let Some(feat_table) = doc.get("features").and_then(|f| f.as_table()) {
            for (feat_name, feat_value) in feat_table.iter() {
                let deps: Vec<String> = feat_value
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                features.insert(feat_name.to_string(), deps);
            }
        }
        Ok(CrateFeatures { name, features })
    }

    fn validate_features(&self, crate_name: &str, features: &[String]) -> Vec<String> {
        features
            .iter()
            .filter(|f| {
                !self
                    .crates
                    .get(crate_name)
                    .map(|c| c.features.contains_key(f.as_str()))
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }
}

// ── Feature Resolver ───────────────────────────────────────────────

struct FeatureResolver {
    schema: Value,
}

impl FeatureResolver {
    fn from_str(schema_str: &str) -> anyhow::Result<Self> {
        let schema: Value =
            serde_json::from_str(schema_str).context("Failed to parse schema JSON")?;
        Ok(FeatureResolver { schema })
    }

    fn resolve(&self, config: &Value) -> anyhow::Result<Vec<String>> {
        let mut features = HashSet::new();
        if let Some(properties) = self.schema.get("properties") {
            self.walk_properties(properties, config, "", &mut features)?;
        }
        let mut result: Vec<String> = features.into_iter().collect();
        result.sort();
        log_info!("Resolved {} features: {}", result.len(), result.join(", "));
        Ok(result)
    }

    fn resolve_crypto(&self, config: &Value) -> String {
        match config
            .pointer("/basic/encryption")
            .and_then(|v| v.as_str())
            .unwrap_or("")
        {
            "aes" => "crypto_aes".to_string(),
            "chacha20" => "crypto_chacha20".to_string(),
            _ => "crypto_xor".to_string(),
        }
    }

    fn walk_properties(
        &self,
        schema_props: &Value,
        config: &Value,
        path: &str,
        features: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        let props = match schema_props.as_object() {
            Some(p) => p,
            None => return Ok(()),
        };

        for (key, prop_schema) in props {
            let config_value = config.get(key);
            let current_path = if path.is_empty() {
                key.clone()
            } else {
                format!("{}.{}", path, key)
            };

            if let Some(annotation) = prop_schema.get("x-cargo-features") {
                self.apply_annotation(annotation, config_value, &current_path, features)?;
            }

            if prop_schema.get("type").and_then(|t| t.as_str()) == Some("array") {
                if let Some(items_schema) = prop_schema.get("items") {
                    if let Some(group) = items_schema.get("x-cargo-features-group") {
                        self.apply_group_annotation(group, config_value, &current_path, features)?;
                    }
                    if let Some(item_props) = items_schema.get("properties") {
                        if let Some(arr) = config_value.and_then(|v| v.as_array()) {
                            for item in arr {
                                self.walk_properties(
                                    item_props,
                                    item,
                                    &format!("{}[]", current_path),
                                    features,
                                )?;
                            }
                        }
                    }
                }
            }

            if prop_schema.get("type").and_then(|t| t.as_str()) == Some("object") {
                if let Some(nested_props) = prop_schema.get("properties") {
                    let nested_config = config_value.unwrap_or(&Value::Null);
                    self.walk_properties(nested_props, nested_config, &current_path, features)?;
                }
            }
        }
        Ok(())
    }

    fn apply_annotation(
        &self,
        annotation: &Value,
        config_value: Option<&Value>,
        path: &str,
        features: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        let anno_type = annotation
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("");
        match anno_type {
            "bool_flag" => {
                if config_value.and_then(|v| v.as_bool()).unwrap_or(false) {
                    if let Some(feat_list) = annotation.get("features").and_then(|f| f.as_array()) {
                        for f in feat_list {
                            if let Some(s) = f.as_str() {
                                log_debug!("  [bool_flag] {} = true -> feature '{}'", path, s);
                                features.insert(s.to_string());
                            }
                        }
                    }
                }
            }
            "enum_map" => {
                let value_str = config_value.and_then(|v| v.as_str()).unwrap_or("");
                if let Some(mapping) = annotation.get("mapping").and_then(|m| m.as_object()) {
                    let matched = mapping.get(value_str).or_else(|| mapping.get("*"));
                    if let Some(feat_list) = matched.and_then(|v| v.as_array()) {
                        for f in feat_list {
                            if let Some(s) = f.as_str() {
                                log_debug!(
                                    "  [enum_map] {} = {:?} -> feature '{}'",
                                    path,
                                    value_str,
                                    s
                                );
                                features.insert(s.to_string());
                            }
                        }
                    }
                }
            }
            "non_empty" => {
                let is_non_empty = config_value
                    .and_then(|v| v.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);
                if is_non_empty {
                    if let Some(feat_list) = annotation.get("features").and_then(|f| f.as_array()) {
                        for f in feat_list {
                            if let Some(s) = f.as_str() {
                                log_debug!("  [non_empty] {} -> feature '{}'", path, s);
                                features.insert(s.to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn apply_group_annotation(
        &self,
        group: &Value,
        config_value: Option<&Value>,
        path: &str,
        features: &mut HashSet<String>,
    ) -> anyhow::Result<()> {
        let items = match config_value.and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => return Ok(()),
        };

        let presence_fields = group.get("presence_fields").and_then(|p| p.as_object());
        let default_features = group.get("default_when_absent").and_then(|d| d.as_array());

        for (idx, item) in items.iter().enumerate() {
            let item_obj = match item.as_object() {
                Some(o) => o,
                None => continue,
            };

            let mut any_presence_hit = false;
            if let Some(pf) = presence_fields {
                for (field_name, feat_list) in pf {
                    let is_present = item_obj
                        .get(field_name)
                        .map(|v| !v.is_null())
                        .unwrap_or(false);
                    if is_present {
                        any_presence_hit = true;
                        if let Some(arr) = feat_list.as_array() {
                            for f in arr {
                                if let Some(s) = f.as_str() {
                                    log_debug!(
                                        "  [presence] {}[{}].{} present -> feature '{}'",
                                        path,
                                        idx,
                                        field_name,
                                        s
                                    );
                                    features.insert(s.to_string());
                                }
                            }
                        }
                    }
                }
            }

            if !any_presence_hit {
                if let Some(defaults) = default_features {
                    for f in defaults {
                        if let Some(s) = f.as_str() {
                            log_debug!(
                                "  [default_when_absent] {}[{}] -> feature '{}'",
                                path,
                                idx,
                                s
                            );
                            features.insert(s.to_string());
                        }
                    }
                }
            }
        }
        Ok(())
    }
} // impl FeatureResolver

// ── Public API ─────────────────────────────────────────────────────

static ENTRY_TOML_PATH: &str = "malefic/Cargo.toml";
static PROTO_TOML_PATH: &str = "malefic-crates/proto/Cargo.toml";

pub(super) fn update_features(
    implant: &crate::config::Implant,
    version: &crate::config::Version,
    source: bool,
) -> anyhow::Result<()> {
    log_info!("Resolving features from configuration via schema...");

    let resolver = FeatureResolver::from_str(CONFIG_SCHEMA)?;
    let config_value = serde_json::to_value(implant)?;
    let mut features = resolver.resolve(&config_value)?;

    // build-type and version features are now managed by malefic-features crate
    // (set via update_features_toml in common_config), not injected into malefic/Cargo.toml

    // Special case: prelude/pack detection
    let has_prelude = {
        let has_pack = implant
            .implants
            .pack
            .as_ref()
            .map_or(false, |p| !p.is_empty());
        has_pack || !implant.implants.prelude.is_empty()
    };
    if has_prelude && !features.contains(&"malefic-autorun".to_string()) {
        log_debug!("  [special] prelude/pack detected -> feature 'malefic-autorun'");
        features.push("malefic-autorun".to_string());
    }

    // Optional: scan workspace and validate
    if let Ok(registry) = FeatureRegistry::scan_workspace(Path::new(".")) {
        let invalid = registry.validate_features("malefic", &features);
        for f in &invalid {
            log_warning!(
                "Feature '{}' not found in crate 'malefic' [features] table",
                f
            );
        }
    }

    log_debug!("Final feature list: {:?}", features);

    // Write entry crate default features
    cargo_features::set_default_features(ENTRY_TOML_PATH, &features)?;

    // Proto crypto special case
    let crypto_feature = resolver.resolve_crypto(&config_value);
    cargo_features::set_default_features(PROTO_TOML_PATH, &[crypto_feature.clone()])?;

    // Handle 3rd-party module toml if enabled
    if implant.implants.enable_3rd {
        cargo_features::update_3rd_toml(&implant.implants.third_modules);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_schema() -> &'static str {
        include_str!("../../config_lint.json")
    }

    #[test]
    fn test_basic_bool_flag() {
        let resolver = FeatureResolver::from_str(test_schema()).unwrap();
        let config = json!({
            "basic": {
                "encryption": "aes",
                "key": "test",
                "cron": "*/5 * * * * * *",
                "jitter": 0.1,
                "retry": 3,
                "targets": [{"address": "127.0.0.1:5555"}],
                "secure": {"enable": true},
                "proxy": {"url": "", "use_env_proxy": false},
                "dga": {"enable": false},
                "guardrail": {"enable": false}
            },
            "implants": {
                "runtime": "tokio",
                "mod": "beacon",
                "register_info": true,
                "hot_load": true,
                "addon": true,
                "modules": [],
                "enable_3rd": false
            }
        });

        let features = resolver.resolve(&config).unwrap();
        // runtime_tokio is no longer in malefic entry features — it's in malefic-features now
        assert!(features.contains(&"beacon".to_string()));
        assert!(features.contains(&"register_info".to_string()));
        assert!(features.contains(&"hot_load".to_string()));
        assert!(features.contains(&"addon".to_string()));
        assert!(features.contains(&"crypto_aes".to_string()));
        assert!(features.contains(&"secure".to_string()));
        assert!(features.contains(&"transport_tcp".to_string()));
    }

    #[test]
    fn test_transport_detection() {
        let resolver = FeatureResolver::from_str(test_schema()).unwrap();
        let config = json!({
            "basic": {
                "encryption": "xor",
                "key": "test",
                "cron": "*/5 * * * * * *",
                "jitter": 0.1,
                "retry": 3,
                "targets": [
                    {"address": "127.0.0.1:5555", "http": {"method": "GET", "path": "/", "version": "1.1", "headers": {}}},
                    {"address": "127.0.0.1:6666"}
                ],
                "proxy": {"url": "", "use_env_proxy": false},
                "dga": {"enable": false},
                "guardrail": {"enable": false}
            },
            "implants": {
                "runtime": "tokio",
                "mod": "beacon",
                "register_info": false,
                "hot_load": false,
                "modules": []
            }
        });

        let features = resolver.resolve(&config).unwrap();
        assert!(features.contains(&"transport_http".to_string()));
        assert!(features.contains(&"transport_tcp".to_string()));
    }

    #[test]
    fn test_crypto_resolver() {
        let resolver = FeatureResolver::from_str(test_schema()).unwrap();

        let config = json!({"basic": {"encryption": "chacha20"}});
        assert_eq!(resolver.resolve_crypto(&config), "crypto_chacha20");

        let config = json!({"basic": {"encryption": "aes"}});
        assert_eq!(resolver.resolve_crypto(&config), "crypto_aes");

        let config = json!({"basic": {"encryption": "unknown"}});
        assert_eq!(resolver.resolve_crypto(&config), "crypto_xor");
    }
}

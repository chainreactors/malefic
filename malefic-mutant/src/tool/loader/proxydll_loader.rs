//! ProxyDLL-based loader generation
//! Reuses existing proxydll module functionality
#![allow(dead_code)]

use super::LoaderGenerator;
use crate::tool::proxydll::update_proxydll;
use anyhow::Result;

/// ProxyDLL loader configuration
#[derive(Debug, Clone, Default)]
pub struct ProxyDllLoader {
    pub raw_dll: String,
    pub proxied_dll: String,
    pub proxy_dll: String,
    pub hijacked_exports: Vec<String>,
    pub use_native_thread: bool,
    pub use_block: bool,
    pub use_prelude: bool,
    pub hijacked_dllmain: bool,
}

impl ProxyDllLoader {
    pub fn new(raw_dll: &str, proxied_dll: &str, proxy_dll: &str) -> Self {
        Self {
            raw_dll: raw_dll.to_string(),
            proxied_dll: proxied_dll.to_string(),
            proxy_dll: proxy_dll.to_string(),
            ..Default::default()
        }
    }

    /// Generate proxydll project files (does not compile)
    pub fn generate_project(&self) -> Result<()> {
        let hijacked: Vec<&str> = self.hijacked_exports.iter().map(|s| s.as_str()).collect();
        update_proxydll(
            &self.raw_dll,
            &self.proxied_dll,
            &self.proxy_dll,
            &hijacked,
            self.use_native_thread,
            self.use_block,
            self.use_prelude,
            self.hijacked_dllmain,
        )
    }
}

impl LoaderGenerator for ProxyDllLoader {
    fn generate(&self, _payload: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!("ProxyDLL generates source files. Use generate_project() method.")
    }

    fn name(&self) -> &'static str {
        "proxydll"
    }
}

//! Loader generation framework
//!
//! Supports multiple loader generation strategies:
//! - Template: Random template-based loader generation
//! - ProxyDLL: DLL proxying loader (existing functionality)
//! - Patch: Binary patching loader

pub mod bdf;
pub mod patch;
pub mod proxydll_loader;
pub mod template;

use anyhow::Result;

pub use patch::PatchLoader;
#[allow(unused_imports)]
pub use proxydll_loader::ProxyDllLoader;
#[allow(unused_imports)]
pub use template::TemplateLoader;

/// Trait for loader generators
#[allow(dead_code)]
pub trait LoaderGenerator {
    /// Generate loader with the given shellcode/payload
    fn generate(&self, payload: &[u8]) -> Result<Vec<u8>>;

    /// Get loader type name
    fn name(&self) -> &'static str;
}

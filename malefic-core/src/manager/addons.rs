use std::collections::HashMap;
use malefic_proto::compress::{compress, decompress};
use crate::config::KEY;
use malefic_proto::crypto::{new_cryptor, Cryptor};

pub struct MaleficAddon {
    pub(crate) name: String,
    pub(crate) r#type: String,
    pub(crate) depend: String,
    pub(crate) content: Vec<u8>,
}

pub struct AddonMap {
    addons: HashMap<String, Box<MaleficAddon>>,
    cryptor: Cryptor,
}

impl AddonMap {
    pub fn new() -> Self {
        let iv: Vec<u8> = KEY.to_vec().iter().rev().cloned().collect();
        let cryptor = new_cryptor(KEY.clone(), iv);
        Self {
            addons: HashMap::new(),
            cryptor,
        }
    }

    pub fn clear(&mut self) {
        self.addons.clear();
    }
    
    pub fn iter(&self) -> std::collections::hash_map::Iter<String, Box<MaleficAddon>> {
        self.addons.iter()
    }
    
    pub(crate) fn insert(&mut self, addon: MaleficAddon) ->  anyhow::Result<()> {
        let compressed = compress(&addon.content)?;
        let encrypted = self.cryptor.encrypt(compressed)?;
        
        let encrypted_addon = Box::new(MaleficAddon {
            name: addon.name.clone(),
            r#type: addon.r#type,
            depend: addon.depend,
            content: encrypted,
        });

        self.addons.insert(addon.name.clone(), encrypted_addon);
        Ok(())
    }
    
    pub(crate) fn get(&mut self, key: &str) -> anyhow::Result<Box<MaleficAddon>> {
        let encrypted_addon = self
            .addons
            .get(key)
            .ok_or_else(||"not found key").unwrap();
        
        let decrypted_content = self.cryptor.decrypt(encrypted_addon.content.clone())?;
        
        let decompressed_content = decompress(&decrypted_content)?;
        
        let decrypted_addon = MaleficAddon {
            name: encrypted_addon.name.clone(),
            r#type: encrypted_addon.r#type.clone(),
            depend: encrypted_addon.depend.clone(),
            content: decompressed_content,
        };

        Ok(Box::from(decrypted_addon))
    }
}

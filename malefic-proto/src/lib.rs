pub mod proto;
pub mod parser;
pub mod crypto;
pub mod compress;

use nanorand::{Rng, WyRand};
use prost::Message;
use proto::implantpb;
use proto::implantpb::spite::Body;


pub fn get_message_len<M: Message>(message: &M) -> usize {
    message.encoded_len()
}

pub fn new_spite(task_id: u32, name: String, body: Body) -> implantpb::Spite {
    implantpb::Spite {
        task_id,
        r#async: true,
        timeout: 0,
        name,
        error: 0,
        status: Option::from(implantpb::Status {
            task_id,
            status: 0,
            error: "".to_string(),
        }),
        body: Some(body),
    }
}

pub fn new_empty_spite(task_id: u32, name: String) -> implantpb::Spite {
    implantpb::Spite {
        task_id,
        r#async: true,
        timeout: 0,
        name,
        error: 0,
        status: Option::from(implantpb::Status {
            task_id,
            status: 0,
            error: "".to_string(),
        }),
        body: Some(Body::Empty(implantpb::Empty::default())),
    }
}
pub fn new_error_spite(task_id: u32, name: String, error: u32) -> implantpb::Spite {
    implantpb::Spite {
        task_id,
        r#async: true,
        timeout: 0,
        name,
        error,
        status: Option::from(implantpb::Status {
            task_id,
            status: 1,
            error: "".to_string(),
        }),
        body: None,
    }
}

pub fn get_sid() -> [u8; 4] {
    let mut rng = WyRand::new();
    let seed = rng.generate();
    let mut seeded_rng = WyRand::new_seed(seed);
    
    let instance_id: [u8; 4];

    if cfg!(debug_assertions) {
        instance_id = [1, 2, 3, 4];
    } else {
        let mut temp_id = [0u8; 4];
        seeded_rng.fill(&mut temp_id);
        instance_id = temp_id;
    }
    instance_id
}


pub fn new_heartbeat(interval: u64, jitter: f64) -> u64 {
    let base_time_ms = (interval * 1000) as f64;
    
    let mut rng = WyRand::new();
    let jitter_factor = if jitter != 0.0 {
        1.0 + (rng.generate_range(0..=((jitter * 2000.0) as u64)) as f64 / 1000.0 - jitter)
    } else {
        1.0
    };

    (base_time_ms * jitter_factor) as u64
}

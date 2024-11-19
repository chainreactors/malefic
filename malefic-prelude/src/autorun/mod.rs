use std::sync::mpsc::{channel, Receiver, Sender};
use anyhow::Result;
use malefic_core::common::error::MaleficError;
use malefic_proto::proto::implantpb::Spite;
use crate::scheduler::PreludeScheduler;

pub struct Autorun {
    scheduler: Option<PreludeScheduler>,  
    task_sender: Sender<Spite>,    // 用于发送任务
    result_receiver: Receiver<Spite>, // 用于接收任务结果
}

impl Autorun {
    pub fn new() -> Result<Autorun, MaleficError> {
        let (task_sender, task_receiver) = channel();
        let (result_sender, result_receiver) = channel();
        
        let scheduler = PreludeScheduler::new(task_receiver, result_sender);

        Ok(Autorun {
            scheduler: Some(scheduler),
            task_sender,
            result_receiver,
        })
    }
    
    pub fn execute(&mut self, tasks: Vec<Spite>) -> Result<Vec<Spite>, MaleficError> {
        // 将 scheduler 移出 Option
        let mut scheduler = self.scheduler.take().unwrap(); // 移动调度器的所有权到局部变量

        // 启动调度器，运行 handler
        std::thread::spawn(move || {
            scheduler.handler().unwrap(); // 调度器移动到线程中
        });

        // 依次将任务发送给调度器
        for task in tasks.iter() {
            self.task_sender.send(task.clone()).unwrap();
        }

        // 接收所有结果
        let mut results = Vec::new();
        for _ in 0..tasks.len() {
            if let Ok(result) = self.result_receiver.recv() {
                results.push(result);
            }
        }

        Ok(results)
    }
}

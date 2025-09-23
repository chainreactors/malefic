use malefic_helper::common::exec;
use malefic_helper::common::exec::is_file_in_use;
use malefic_proto::proto::modulepb::ExecResponse;
use crate::prelude::*;

pub struct Open {}

#[async_trait]
#[module_impl("open")]
impl Module for Open {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for Open {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, sender: &mut malefic_proto::module::Output) -> malefic_proto::module::ModuleResult {
        let request = check_request!(receiver, Body::ExecRequest)?;
        if is_file_in_use(&request.path) && request.singleton {
            Ok(TaskResult::new_with_body(id, Body::ExecResponse(ExecResponse{
                status_code: 0,
                stdout: "File is in use, skipped".as_bytes().to_vec(),
                stderr: vec![],
                pid: 0,
                end: true,
            })))
        }else{
            exec::shell_execute(&request.path, "open")?;
            Ok(TaskResult::new_with_body(id, Body::ExecResponse(ExecResponse::default())))
        }
    }
}
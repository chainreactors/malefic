use malefic_proto::proto::modulepb::Response;
use crate::prelude::*;

pub struct Whoami {}

#[async_trait]
#[module_impl("whoami")]
impl Module for Whoami {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for Whoami {
     async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, _sender: &mut malefic_proto::module::Output) -> ModuleResult {
        let _ = check_request!(receiver, Body::Request)?;
        let mut response = Response::default();
        response.output = malefic_helper::common::sysinfo::username();
        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}
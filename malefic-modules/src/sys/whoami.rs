use crate::prelude::*;
use malefic_proto::proto::modulepb::Response;

pub struct Whoami {}

#[async_trait]
#[module_impl("whoami")]
impl Module for Whoami {}

#[async_trait]
#[obfuscate]
impl malefic_module::ModuleImpl for Whoami {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        _sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let _ = check_request!(receiver, Body::Request)?;
        let mut response = Response::default();
        response.output = malefic_sysinfo::username();
        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}

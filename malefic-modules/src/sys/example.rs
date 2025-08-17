use malefic_proto::module::TaskError::NotImpl;
use crate::prelude::*;

pub struct Example {}

#[async_trait]
#[module_impl("example")]
impl Module for Example {}

#[async_trait]
impl ModuleImpl for Example {
     #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, sender: &mut malefic_proto::module::Output) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;
        if request.input == "ok" {
            let mut response = Response::default();
            response.output = "ok".to_string();
            Ok(TaskResult::new_with_body(id, Body::Response(response)))
        } else {
            Err(anyhow::anyhow!(NotImpl))
        }
    }
}

use async_trait::async_trait;
use malefic_trait::module_impl;
use crate::{check_request, Module, ModuleImpl, Result, TaskResult};
use malefic_proto::proto::modulepb::Response;
use malefic_proto::proto::implantpb::spite::Body;
use crate::TaskError::{NotImpl};


pub struct Example {}

#[async_trait]
#[module_impl("example")]
impl Module for Example {}

#[async_trait]
impl ModuleImpl for Example {
     #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
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

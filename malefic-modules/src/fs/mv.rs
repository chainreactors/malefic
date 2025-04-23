use async_trait::async_trait;
use malefic_trait::module_impl;
use crate::{check_request, Module, Result, check_field, TaskResult};
use malefic_proto::proto::implantpb::spite::Body;


pub struct Mv {}

#[async_trait]
#[module_impl("mv")]
impl Module for Mv {}

#[async_trait]
impl crate::ModuleImpl for Mv {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::Request)?;

        let args = check_field!(request.args, 2)?;

        if let [src, dst] = &args[..] {
            std::fs::rename(&src, &dst)?;
        }

        Ok(TaskResult::new(id))
    }
}
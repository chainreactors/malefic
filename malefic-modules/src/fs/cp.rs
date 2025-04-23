use async_trait::async_trait;
use malefic_trait::module_impl;
use crate::{check_request, Module, Result, check_field, TaskResult};
use malefic_proto::proto::implantpb::spite::Body;


pub struct Cp {}

#[async_trait]
#[module_impl("cp")]
impl Module for Cp{}

#[async_trait]
impl crate::ModuleImpl for Cp {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::Request)?;
        let params = check_field!(request.args, 2)?;

        std::fs::copy(&params[0], &params[1])?;

        Ok(TaskResult::new(id))
    }
}
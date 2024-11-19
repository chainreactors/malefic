use crate::{Module, TaskResult, check_request, Result, check_field};
use malefic_proto::proto::implantpb::spite::Body;
use async_trait::async_trait;
use malefic_trait::module_impl;

pub struct Kill {}

#[async_trait]
#[module_impl("kill")]
impl Module for Kill {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::Request)?;

        let pid = check_field!(request.input)?;

        malefic_helper::common::process::kill(pid.parse()?)?;

        Ok(TaskResult::new(id)) // 响应体为空
    }
}
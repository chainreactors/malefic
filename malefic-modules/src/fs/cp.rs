use crate::prelude::*;


pub struct Cp {}

#[async_trait]
#[module_impl("cp")]
impl Module for Cp{}

#[async_trait]
impl malefic_proto::module::ModuleImpl for Cp {
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, _: &mut malefic_proto::module::Output) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;
        let params = check_field!(request.args, 2)?;

        std::fs::copy(&params[0], &params[1])?;

        Ok(TaskResult::new(id))
    }
}
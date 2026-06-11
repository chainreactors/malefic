use crate::prelude::*;

pub struct Cd {}

#[async_trait]
#[module_impl("cd")]
impl Module for Cd {}

#[async_trait]
#[obfuscate]
impl ModuleImpl for Cd {
    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;

        // Try to set current directory, return error if failed
        std::env::set_current_dir(&request.input)?;

        // Normal logic
        let mut response = Response::default();
        let output = std::env::current_dir()?;
        response.output = output.to_string_lossy().to_string();

        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}

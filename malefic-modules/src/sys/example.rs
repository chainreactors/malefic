use malefic_proto::module::TaskError::NotImpl;
use crate::prelude::*;

pub struct Example {}

#[async_trait]
#[module_impl("example")]
impl Module for Example {}

#[async_trait]
impl ModuleImpl for Example {
     #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, sender: &mut malefic_proto::module::Output) -> ModuleResult {
         let request = check_request!(receiver, Body::Request)?;
         let example_return = "this is 1n73rn4l 0f m4l1c3";
         let mut response = Response::default();
         response.output = example_return.to_string();
         Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}

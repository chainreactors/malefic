use crate::prelude::*;


pub struct Pwd {}

#[async_trait]
#[module_impl("pwd")]
impl Module for Pwd {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for Pwd {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, sender: &mut malefic_proto::module::Output) -> ModuleResult {
        let _ = check_request!(receiver, Body::Request)?;

        let mut response = Response::default();
        let output = std::env::current_dir()?;
        response.output = output.to_string_lossy().to_string();

        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}

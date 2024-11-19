use crate::{Module, TaskResult, check_request, Result, check_field};
use malefic_proto::proto::implantpb::spite::Body;

use async_trait::async_trait;
use malefic_trait::module_impl;

pub struct Chown {}

#[async_trait]
#[module_impl("chown")]
impl Module for Chown {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::ChownRequest)?;

        // 检查 uid 和 gid 是否存在，并尝试将它们解析为 Uid 和 Gid
        let uid = check_field!(request.uid)?.parse::<u32>()?;
        let gid = check_field!(request.gid)?.parse::<u32>()?;
        let path = check_field!(request.path)?;

        malefic_helper::common::filesys::chown(&path, uid, gid)?;

        Ok(TaskResult::new(id))
    }
}
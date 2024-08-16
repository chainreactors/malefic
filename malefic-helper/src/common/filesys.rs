use std::{env, io};

#[cfg(target_family = "unix")]
pub fn chown(path: &str, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::path::Path;
    use std::os::unix::ffi::OsStrExt;
    let path = Path::new(path);
    let ret = unsafe {
        libc::chown(path.as_os_str().as_bytes().as_ptr() as _, uid, gid)
    };
    if ret.eq(&0) {
            Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
    // chown(Path::new(path), Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
}

#[cfg(target_family = "unix")]
pub fn chmod(path: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::path::Path::new(path);
    let mut permissions = path.metadata()?.permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions)

    // std::fs::set_permissions(path, std::fs::Permissions::from(mode))
}


pub fn check_sum(path: &str) -> std::io::Result<String> {
    use std::fs::File;
    use std::io::{BufReader, Read};
    use sha2::{Sha256, Digest};
    // use std::path::Path;

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    // let file_extensions = Path::new(path)
    //     .extension()
    //     .and_then(std::ffi::OsStr::to_str);
    let mut buffer = [0; 1024];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}


pub(crate) fn get_cwd() -> Result<String, io::Error> {
    let path = env::current_dir()?;
    Ok(path.display().to_string())
}

pub fn get_executable_path() -> Result<String, io::Error> {
    let path = env::current_exe()?;
    Ok(path.display().to_string())
}
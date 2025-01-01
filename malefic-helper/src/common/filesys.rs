use std::{env, io};
use std::path::{Path, PathBuf};

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

#[cfg(target_os = "windows")]
pub fn get_file_mode(meta: &dyn std::os::windows::fs::MetadataExt) -> u32 {
    meta.file_attributes()
}

#[cfg(target_family = "unix")]
pub fn get_file_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}


pub fn lookup(file_name: &str) -> PathBuf {
    let mut path = PathBuf::from(file_name);

    #[cfg(windows)]
    {
        if path.extension().is_none() {
            path.set_extension("exe");
        }
    }
    
    if path.is_absolute() {
        return path.to_path_buf();
    }

    if let Ok(current_dir) = env::current_dir() {
        let relative_path = current_dir.join(file_name);
        if relative_path.is_file() {
            return relative_path;
        }
    }

    if let Ok(path_env) = env::var("PATH") {
        #[cfg(windows)]
        let separator = ';';
        #[cfg(not(windows))]
        let separator = ':';

        for dir in path_env.split(separator) {
            let executable_path = Path::new(dir).join(file_name);
            if executable_path.is_file() {
                return executable_path;
            }
        }
    }

    Path::new(file_name).to_path_buf()
}

pub fn get_binary(file: &str) -> anyhow::Result<(Vec<u8>, String)> {
    let path = lookup(file);

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("not found file"))? // 如果没有文件名，直接返回 Err
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid UTF-8 in file name"))? // 如果文件名无法转换为字符串，直接返回 Err
        .to_string();

    let content = std::fs::read(&path)?;

    Ok((content, file_name))
}

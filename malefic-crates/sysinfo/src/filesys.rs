use std::path::{Path, PathBuf};
use std::{env, io};

#[cfg(target_family = "unix")]
pub fn chown(path: &str, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = Path::new(path);
    let ret = unsafe { libc::chown(path.as_os_str().as_bytes().as_ptr() as _, uid, gid) };
    if ret.eq(&0) {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_family = "unix")]
pub fn chmod(path: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::path::Path::new(path);
    let mut permissions = path.metadata()?.permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions)
}

pub fn check_sum(path: &str) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::{BufReader, Read};

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
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

pub fn check_sum_bytes(bytes: &[u8]) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn check_sum_read<R: std::io::Read>(reader: &mut R) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 4096];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn get_cwd() -> Result<String, io::Error> {
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
        let relative_path = current_dir.join(&path);
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
            let executable_path = Path::new(dir).join(&path);
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
        .ok_or_else(|| anyhow::anyhow!("not found file"))?
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid UTF-8 in file name"))?
        .to_string();

    let content = std::fs::read(&path)?;

    Ok((content, file_name))
}

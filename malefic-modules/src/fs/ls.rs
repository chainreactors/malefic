use malefic_proto::proto::modulepb::{FileInfo, LsResponse};
use crate::prelude::*;

pub struct Ls {}

#[async_trait]
#[module_impl("ls")]
impl Module for Ls {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for Ls {
#[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, sender: &mut malefic_proto::module::Output) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;
        let path = check_field!(request.input)?;
        let mut entries = vec![];
        let read_dir = std::fs::read_dir(&path)?;
        // let abs_path = std::fs::canonicalize(&path)?;
        
        for entry in read_dir {
            let entry = entry?;
            let p = entry.path();
            let metadata = entry.metadata()?;
            let mode = malefic_helper::common::filesys::get_file_mode(&metadata);
            let link = if metadata.file_type().is_symlink() {
                std::fs::read_link(&p)
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or(String::new())
            } else {
                String::new()
            };
            entries.push(FileInfo {
                name: p.file_name().map(|os_str| os_str.to_string_lossy().to_string()).unwrap_or(String::new()),
                is_dir: metadata.is_dir(),
                size: metadata.len(),
                mode,
                mod_time: metadata.modified()?.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::from_secs(0))
                    .as_secs() as i64, 
                link, 
            });
        }


        Ok(TaskResult::new_with_body(id, Body::LsResponse(LsResponse {
            path, 
            exists: true,
            files: entries,
        })))
    }
}
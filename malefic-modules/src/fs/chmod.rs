use crate::prelude::*;

pub struct Chmod {}

#[async_trait]
#[module_impl("chmod")]
impl Module for Chmod {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for Chmod {
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, _sender: &mut malefic_proto::module::Output) -> Result {
        let request = check_request!(receiver, Body::Request)?;

        let args = check_field!(request.args, 2)?;

        if let [path, mode_str] = &args[..] {
            let mode = u32::from_str_radix(&mode_str.trim(), 8)?;
            malefic_helper::common::filesys::chmod(&path, mode)?;
        }

        Ok(TaskResult::new(id))
    }
}
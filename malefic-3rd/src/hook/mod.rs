use async_trait::async_trait;
use detour::RawDetour;
use std::ffi::{CString, c_void};
use winapi::um::{
    libloaderapi::GetModuleHandleA, 
    libloaderapi::GetProcAddress, 
    winnt::LPCSTR,
};
use crate::prelude::*;

/**
 * Demo for hook any funcs
 * Such as MessageBoxA
 */

type FuncFn = unsafe extern "system" fn(
    hwnd: *mut c_void,
    text: LPCSTR,
    caption: LPCSTR,
    utype: u32,
) -> i32;


unsafe extern "system" fn replace_func(
    hwnd: *mut c_void,
    _text: LPCSTR,
    _caption: LPCSTR,
    utype: u32,
) -> i32 {

    // 新的消息文本
    let new_text = b"Hooked by retour-rs!\0";
    let new_caption = b"Intercepted!\0";

    // 调用原始函数
    let original = ORIGINAL.expect("Original function not set!");
    original(hwnd, new_text.as_ptr() as _, new_caption.as_ptr() as _, utype)
}




struct Hook {}

static mut DETOUR: Option<RawDetour> = None;
static mut ORIGINAL: Option<FuncFn> = None;

#[async_trait]
#[module_impl("hook")]
impl Module for Hook {}

#[async_trait]
impl ModuleImpl for Hook {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let request = check_request!(receiver, Body::Request)?;
        let input = check_field!(request.input)?;
        if input.eq(&"hook") {
            unsafe {
                let args = check_field!(request.args)?;
                if args.len().ne(&2) {
                    return Err(anyhow!("Need two arguments: dll name and func name"));
                }
                let module_name = match CString::new(args[0].clone()) {
                    Ok(name) => name,
                    Err(e) => {
                        return Err(anyhow!(e.to_string()))
                    }
                };
                let func_name = match CString::new(args[1].clone()) {
                    Ok(name) => name,
                    Err(e) => {
                        return Err(anyhow!(e.to_string()))
                    }
                };
                let module_handle = GetModuleHandleA(module_name.as_ptr() as _);
                if module_handle.is_null() {
                    return Err(anyhow!("module handle get failed"));
                }
                
                let func_addr = GetProcAddress(module_handle, func_name.as_ptr() as _);
                if func_addr.is_null() {
                    return Err(anyhow!("func handle get failed"));
                }

                let detour = RawDetour::new(func_addr as * const (), replace_func as *const ());
                match detour {
                    Ok(detour) => {
                        let trampoline = detour.trampoline();
                        ORIGINAL = Some(std::mem::transmute(trampoline as *const ()));
                        match detour.enable() {
                            Ok(_) => {
                                 DETOUR = Some(detour);
                            },
                            Err(e) => {
                                return Err(anyhow!(e.to_string()));
                            }
                        }
                    }
                    Err(e) => {
                        return Err(anyhow!(e.to_string()));
                    }
                }

            }
        } else if input.eq(&"unhook") {
            unsafe {
                if let Some(detour) = DETOUR.take() {
                    detour.disable().ok();
                }   
            }
        } else {
            return Err(anyhow!("Unknown input, Need hook/unhook"));
        }
        

        let resp = Response::default();
        Ok(TaskResult::new_with_body(id, Body::Response(resp)))
    }
}
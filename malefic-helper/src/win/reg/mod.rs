use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, RegDeleteValueW, RegCloseKey, HKEY, KEY_READ, KEY_WRITE, KEY_SET_VALUE, REG_SZ, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS, REG_NONE, REG_SAM_FLAGS, RegCreateKeyExW, REG_OPTION_NON_VOLATILE, RegDeleteKeyW, RegDeleteKeyExW, RegQueryInfoKeyW};
use std::ptr;
use std::ffi::OsString;
use std::os::windows::ffi::{OsStringExt};
use windows::core::PCWSTR;
use crate::CommonError;
pub struct Registry;
impl Registry {
    pub fn new() -> Self {
        Registry
    }
    fn open(&self, hive: &str, path: &str, flag: REG_SAM_FLAGS) -> Result<HKEY, CommonError> {
        let hkey = self.string_to_hkey(hive)?;
        let sub_key: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey_result = HKEY(0);
        unsafe {
            let status = RegOpenKeyExW(
                hkey,
                PCWSTR(sub_key.as_ptr()),
                0,
                flag,
                &mut hkey_result
            );
            if status == WIN32_ERROR(2) && flag == KEY_WRITE {
                let status = RegCreateKeyExW(
                    hkey, // 父键的句柄
                    PCWSTR(sub_key.as_ptr()),
                    0,
                    None, // 类字符串，通常为空
                    REG_OPTION_NON_VOLATILE, // 键存储选项
                    KEY_WRITE, // 所需的安全访问
                    Some(ptr::null()), // 安全属性
                    &mut hkey_result, // 打开或创建的键的句柄
                    Some(ptr::null_mut()), // 确定函数是创建了键还是打开了键
                );
                if status != ERROR_SUCCESS {
                    return Err(CommonError::Win32Error(status.0));
                }
            }else if status != ERROR_SUCCESS {
                return Err(CommonError::Win32Error(status.0));
            }
        }
        Ok(hkey_result)
    }

    fn close(&self, hkey: HKEY) {
        unsafe {
            RegCloseKey(hkey);
        }
    }
    pub fn read_value(&self, hive: &str, path: &str, key: &str) -> Result<String, CommonError> {
        let key_name: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            let hkey = self.open(hive, path, KEY_READ)?;

            let mut value_type = REG_NONE;
            let mut value_size = 0;

            let mut status = RegQueryValueExW(
                hkey,
                PCWSTR(key_name.as_ptr()),
                Some(ptr::null_mut()),
                Some(&mut value_type),
                Some(ptr::null_mut()),
                Some(&mut value_size)
            );
            if status != ERROR_SUCCESS {
                RegCloseKey(hkey);
                return Err(CommonError::Win32Error(status.0));
            }
            let mut value = vec![0u16; value_size as usize];
            status = RegQueryValueExW(hkey,
                                      PCWSTR(key_name.as_ptr()),
                                      Some(ptr::null_mut()),
                                      Some(&mut value_type),
                                      Some(value.as_mut_ptr() as *mut u8),
                                      Some(&mut value_size)
            );
            if status != ERROR_SUCCESS {
                RegCloseKey(hkey);
                return Err(CommonError::Win32Error(status.0));
            }
            let os_str: OsString = OsString::from_wide(&value);
            RegCloseKey(hkey);
            Ok(os_str.to_string_lossy().trim_matches('\0').to_string())
        }
    }

    // pub fn list_value(&self, hive: &str, path: &str) -> Result<HashMap<>, CommonError>{
    //     let hkey = self.open(hive, path, KEY_READ)?;
    //
    //     unsafe {
    //         let mut value_count: u32 = 0;
    //         let mut max_value_name_len: u32 = 0;
    //         let query_status = RegQueryInfoKeyW(
    //             hkey,
    //             ,
    //             null_mut(),
    //             null_mut(),
    //             null_mut(),
    //             null_mut(),
    //             null_mut(),
    //             Some(&mut value_count),
    //             Some(&mut max_value_name_len),
    //             null_mut(),
    //             null_mut(),
    //             null_mut(),
    //         );
    //         if query_status != ERROR_SUCCESS.0 {
    //             RegCloseKey(hkey);
    //             return Err(windows::core::Error::from_win32(query_status));
    //         }
    //
    //         for i in 0..value_count {
    //             let mut value_name_len = max_value_name_len + 1;
    //             let mut value_name: Vec<u16> = vec![0; value_name_len as usize];
    //             let mut data_len: u32 = 0;
    //             let mut value_type: REG_VALUE_TYPE = REG_VALUE_TYPE(0);
    //             let enum_status = RegEnumValueW(
    //                 hkey,
    //                 i,
    //                 value_name.as_mut_ptr(),
    //                 &mut value_name_len,
    //                 null_mut(),
    //                 &mut value_type,
    //                 null_mut(),
    //                 &mut data_len,
    //             );
    //             if enum_status == ERROR_SUCCESS.0 {
    //                 value_name.truncate(value_name_len as usize);
    //                 let name = OsString::from_wide(&value_name).to_string_lossy().into_owned();
    //                 println!("Value #{}: Name: {}", i, name);
    //             }
    //         }
    //
    //         RegCloseKey(hkey);
    //     }
    //
    //     Ok(())
    // }

    pub fn write(&self, hive: &str, path: &str, key: &str, value: &str) -> Result<(), CommonError> {
        let hkey = self.open(hive, path, KEY_WRITE)?;
        let value_name: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
        let mut data: Vec<u8> = value.as_bytes().to_owned();
        data.push(0);

        unsafe {
            let status = RegSetValueExW(
                hkey,
                PCWSTR(value_name.as_ptr()),
                0,
                REG_SZ,
                Some(&data));
            RegCloseKey(hkey);
            if status != ERROR_SUCCESS{
                return Err(CommonError::Win32Error(status.0));
            }
        }
        Ok(())
    }

    pub fn delete_value(&self, hive: &str, key: &str, value: &str) -> Result<(), CommonError> {
        let hkey = self.open(hive, key, KEY_SET_VALUE)?;
        let value_name: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let status = RegDeleteValueW(hkey, PCWSTR(value_name.as_ptr()));
            if status != ERROR_SUCCESS {
                return Err(CommonError::Win32Error(status.0));
            }
            RegCloseKey(hkey);
        }

        Ok(())
    }

    fn string_to_hkey(&self, hive: &str) -> Result<HKEY, CommonError> {
        match hive {
            "HKEY_CLASSES_ROOT" => Ok(HKEY_CLASSES_ROOT),
            "HKEY_CURRENT_USER" => Ok(HKEY_CURRENT_USER),
            "HKEY_LOCAL_MACHINE" => Ok(HKEY_LOCAL_MACHINE),
            "HKEY_USERS" => Ok(HKEY_USERS),
            _ => Err(CommonError::Win32Error(2)),
        }
    }
}
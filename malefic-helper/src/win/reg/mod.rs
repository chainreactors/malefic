use crate::debug;
use crate::win::common::to_wide_string;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::ptr::null_mut;
use strum_macros::{Display, EnumString};
use windows::core::{Error, Result, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    RegCreateKeyExW, RegDeleteKeyExW, RegDeleteTreeW, RegDeleteValueW, RegEnumKeyExW,
    RegEnumValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, KEY_ALL_ACCESS, KEY_READ,
    KEY_WRITE, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE,
    REG_QWORD, REG_SZ, REG_VALUE_TYPE,
};

#[cfg_attr(debug_assertions, derive(Debug))]
pub enum RegistryValue {
    String(String),
    Dword(u32),
    Qword(u64),
    Binary(Vec<u8>),
    MultiString(Vec<String>),
    ExpandString(String),
}

// 实现将 RegistryValue 转换为 String 的方法
impl fmt::Display for RegistryValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryValue::String(val) => write!(f, "{}", val),
            RegistryValue::Dword(val) => write!(f, "{}", val),
            RegistryValue::Qword(val) => write!(f, "{}", val),
            RegistryValue::Binary(val) => write!(f, "{:?}", val),
            RegistryValue::MultiString(val) => write!(f, "{:?}", val),
            RegistryValue::ExpandString(val) => write!(f, "{}", val),
        }
    }
}

// 实现从缓冲区中读取并转换为 RegistryValue
impl RegistryValue {
    pub fn from_buffer(data_type: REG_VALUE_TYPE, buffer: &[u8], buffer_size: u32) -> Self {
        match data_type {
            REG_SZ | REG_EXPAND_SZ => {
                let wide_buffer_len = (buffer_size as usize / 2).saturating_sub(1);
                let content = String::from_utf16_lossy(
                    &buffer[..wide_buffer_len * 2]
                        .chunks(2)
                        .map(|s| u16::from_le_bytes([s[0], s[1]]))
                        .collect::<Vec<u16>>(),
                );
                if data_type == REG_SZ {
                    RegistryValue::String(content)
                } else {
                    RegistryValue::ExpandString(content)
                }
            }
            REG_DWORD => {
                let data: u32 = u32::from_ne_bytes(buffer[..4].try_into().unwrap_or([0, 0, 0, 0]));
                RegistryValue::Dword(data)
            }
            REG_QWORD => {
                let data: u64 =
                    u64::from_ne_bytes(buffer[..8].try_into().unwrap_or([0, 0, 0, 0, 0, 0, 0, 0]));
                RegistryValue::Qword(data)
            }
            REG_BINARY => RegistryValue::Binary(buffer[..buffer_size as usize].to_vec()),
            REG_MULTI_SZ => {
                let mut result = Vec::new();
                let mut cur = Vec::new();
                for chunk in buffer.chunks_exact(2) {
                    let chr = u16::from_le_bytes([chunk[0], chunk[1]]);
                    if chr == 0 {
                        if !cur.is_empty() {
                            let s = String::from_utf16_lossy(&cur);
                            if !s.is_empty() {
                                result.push(s);
                            }
                            cur.clear();
                        }
                    } else {
                        cur.push(chr);
                    }
                }
                RegistryValue::MultiString(result)
            }
            _ => RegistryValue::String("Unsupported type".to_string()),
        }
    }
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, Copy, EnumString, Display)]
pub enum RegistryHive {
    #[strum(serialize = "HKEY_CLASSES_ROOT", serialize = "HKCR")]
    ClassesRoot,
    #[strum(serialize = "HKEY_CURRENT_USER", serialize = "HKCU")]
    CurrentUser,
    #[strum(serialize = "HKEY_LOCAL_MACHINE", serialize = "HKLM")]
    LocalMachine,
    #[strum(serialize = "HKEY_USERS", serialize = "HKU")]
    Users,
    #[strum(serialize = "HKEY_PERFORMANCE_DATA", serialize = "HKPD")]
    PerformanceData,
    #[strum(serialize = "HKEY_PERFORMANCE_TEXT", serialize = "HKPT")]
    PerformanceText,
    #[strum(serialize = "HKEY_PERFORMANCE_NLSTEXT")]
    PerformanceNlsText,
    #[strum(serialize = "HKEY_CURRENT_CONFIG", serialize = "HKCC")]
    CurrentConfig,
    #[strum(serialize = "HKEY_DYN_DATA")]
    DynData,
    #[strum(serialize = "HKEY_CURRENT_USER_LOCAL_SETTINGS")]
    CurrentUserLocalSettings,
}

impl RegistryHive {
    pub fn to_hkey(&self) -> HKEY {
        match self {
            RegistryHive::ClassesRoot => windows::Win32::System::Registry::HKEY_CLASSES_ROOT,
            RegistryHive::CurrentUser => windows::Win32::System::Registry::HKEY_CURRENT_USER,
            RegistryHive::LocalMachine => windows::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            RegistryHive::Users => windows::Win32::System::Registry::HKEY_USERS,
            RegistryHive::PerformanceData => {
                windows::Win32::System::Registry::HKEY_PERFORMANCE_DATA
            }
            RegistryHive::PerformanceText => {
                windows::Win32::System::Registry::HKEY_PERFORMANCE_TEXT
            }
            RegistryHive::PerformanceNlsText => {
                windows::Win32::System::Registry::HKEY_PERFORMANCE_NLSTEXT
            }
            RegistryHive::CurrentConfig => windows::Win32::System::Registry::HKEY_CURRENT_CONFIG,
            RegistryHive::DynData => windows::Win32::System::Registry::HKEY_DYN_DATA,
            RegistryHive::CurrentUserLocalSettings => {
                windows::Win32::System::Registry::HKEY_CURRENT_USER_LOCAL_SETTINGS
            }
        }
    }
}

pub struct RegistryKey {
    hkey: HKEY,
}

impl RegistryKey {
    pub fn open(hive: RegistryHive, subkey: &str) -> Result<Self> {
        let hkey_root = hive.to_hkey();
        let subkey_wide = to_wide_string(subkey);
        let mut hkey: HKEY = HKEY(null_mut());
        debug!("Opening registry key: {:?} {:?}", hive, subkey);

        unsafe {
            // 定义权限尝试的顺序
            let access_levels = [
                KEY_ALL_ACCESS,
                KEY_READ | KEY_WRITE,
                KEY_READ,
            ];

            let mut last_status = ERROR_SUCCESS;

            for &access in &access_levels {
                let status = RegOpenKeyExW(
                    hkey_root,
                    PCWSTR(subkey_wide.as_ptr()),
                    0,
                    access,
                    &mut hkey,
                );

                if status.0 == 0 {
                    return Ok(RegistryKey { hkey });
                }

                last_status = status;
                debug!("Failed to open registry key with access {:?}: {}", access, status.0);

                // 如果不是权限错误，立即退出循环
                if status.0 != 5 {
                    break;
                }
            }

            debug!("Failed to open registry key {} {}", last_status.0, Error::from_win32());
            Err(Error::from_win32())
        }
    }

    pub fn create(hive: RegistryHive, subkey: &str) -> Result<Self> {
        let hkey_root = hive.to_hkey();
        let subkey_wide = to_wide_string(subkey);
        let mut hkey: HKEY = HKEY(null_mut());

        unsafe {
            // 尝试使用完整权限创建
            let mut status = RegCreateKeyExW(
                hkey_root,
                PCWSTR(subkey_wide.as_ptr()),
                0,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS,
                None,
                &mut hkey,
                None,
            );

            if status.0 != 0 {
                debug!(
                    "Failed to create registry key with KEY_ALL_ACCESS: {}",
                    status.0
                );
                // 如果是权限问题（错误码5），尝试使用有限权限
                if status.0 == 5 {
                    status = RegCreateKeyExW(
                        hkey_root,
                        PCWSTR(subkey_wide.as_ptr()),
                        0,
                        None,
                        REG_OPTION_NON_VOLATILE,
                        KEY_READ | KEY_WRITE,
                        None,
                        &mut hkey,
                        None,
                    );
                }
            }

            if status.0 != 0 {
                debug!("Failed to create registry key: {}", status.0);
                return Err(Error::from_win32());
            }
        }

        Ok(RegistryKey { hkey })
    }

    pub fn query_value(&self, name: &str) -> Result<RegistryValue> {
        let name_wide = to_wide_string(name);
        let mut data_type = REG_VALUE_TYPE(0);
        let mut buffer = vec![0u8; 256]; // 缓冲区大小根据需要调整
        let mut buffer_size = buffer.len() as u32;

        unsafe {
            let status = RegQueryValueExW(
                self.hkey,
                PCWSTR(name_wide.as_ptr()),
                None,
                Some(&mut data_type),
                Some(buffer.as_mut_ptr()),
                Some(&mut buffer_size),
            );

            if status.0 != 0 {
                return Err(Error::from_win32());
            }

            // 调用 RegistryValue 的 from_buffer 方法，将缓冲区转换为 RegistryValue
            Ok(RegistryValue::from_buffer(data_type, &buffer, buffer_size))
        }
    }

    pub fn delete_key(&self, subkey: Option<&str>) -> Result<()> {
        if let Some(subkey) = subkey {
            let subkey_wide = to_wide_string(subkey);
            let status: WIN32_ERROR =
                unsafe { RegDeleteTreeW(self.hkey, PCWSTR(subkey_wide.as_ptr())) };
            if status.0 != 0 && status.0 != 2 {
                return Err(Error::from_win32());
            }
            let status: WIN32_ERROR =
                unsafe { RegDeleteKeyExW(self.hkey, PCWSTR(subkey_wide.as_ptr()), 0, 0) };
            if status.0 != 0 {
                return Err(Error::from_win32());
            }
        } else {
            let empty_subkey = to_wide_string(""); // 空字符串
            let status: WIN32_ERROR =
                unsafe { RegDeleteKeyExW(self.hkey, PCWSTR(empty_subkey.as_ptr()), 0, 0) };
            if status.0 != 0 {
                return Err(Error::from_win32());
            }
        }
        Ok(())
    }

    pub fn delete_value(&self, value_name: &str) -> Result<()> {
        let value_name_wide = to_wide_string(value_name);
        unsafe {
            let status = RegDeleteValueW(self.hkey, PCWSTR(value_name_wide.as_ptr()));
            if status.0 != 0 {
                return Err(Error::from_win32());
            }
        }
        Ok(())
    }

    pub fn set_value(&self, name: &str, value: RegistryValue) -> Result<()> {
        let name_wide = to_wide_string(name);
        unsafe {
            let status = match value {
                RegistryValue::String(data) => {
                    let data_wide = to_wide_string(&data);
                    let data_slice = std::slice::from_raw_parts(
                        data_wide.as_ptr() as *const u8,
                        data_wide.len() * 2,
                    );
                    RegSetValueExW(
                        self.hkey,
                        PCWSTR(name_wide.as_ptr()),
                        0,
                        REG_SZ,
                        Some(data_slice),
                    )
                }
                RegistryValue::Dword(data) => {
                    let data_bytes = data.to_ne_bytes();
                    RegSetValueExW(
                        self.hkey,
                        PCWSTR(name_wide.as_ptr()),
                        0,
                        REG_DWORD,
                        Some(&data_bytes),
                    )
                }
                RegistryValue::Qword(data) => {
                    let data_bytes = data.to_ne_bytes();
                    RegSetValueExW(
                        self.hkey,
                        PCWSTR(name_wide.as_ptr()),
                        0,
                        REG_QWORD,
                        Some(&data_bytes),
                    )
                }
                RegistryValue::Binary(data) => RegSetValueExW(
                    self.hkey,
                    PCWSTR(name_wide.as_ptr()),
                    0,
                    REG_BINARY,
                    Some(&data),
                ),
                RegistryValue::MultiString(data) => {
                    let data_wide: Vec<u16> = data
                        .iter()
                        .flat_map(|s| to_wide_string(s))
                        .chain(Some(0))
                        .collect();
                    let data_slice = std::slice::from_raw_parts(
                        data_wide.as_ptr() as *const u8,
                        data_wide.len() * 2,
                    );
                    RegSetValueExW(
                        self.hkey,
                        PCWSTR(name_wide.as_ptr()),
                        0,
                        REG_MULTI_SZ,
                        Some(data_slice),
                    )
                }
                RegistryValue::ExpandString(data) => {
                    let data_wide = to_wide_string(&data);
                    let data_slice = std::slice::from_raw_parts(
                        data_wide.as_ptr() as *const u8,
                        data_wide.len() * 2,
                    );
                    RegSetValueExW(
                        self.hkey,
                        PCWSTR(name_wide.as_ptr()),
                        0,
                        REG_EXPAND_SZ,
                        Some(data_slice),
                    )
                }
            };

            if status.0 != 0 {
                debug!("Failed to set registry value: {}", status.0);
                return Err(Error::from_win32());
            }
        }

        Ok(())
    }

    pub fn list_subkeys(&self) -> Result<Vec<String>> {
        let mut index = 0;
        let mut subkeys = Vec::new();

        loop {
            let mut name = vec![0u16; 256];
            let mut name_len = name.len() as u32;

            unsafe {
                let status = RegEnumKeyExW(
                    self.hkey,
                    index,
                    PWSTR(name.as_mut_ptr()),
                    &mut name_len,
                    None,
                    PWSTR(null_mut()),
                    None,
                    None,
                );

                if status.0 == 0 {
                    let subkey_name = String::from_utf16_lossy(&name[..name_len as usize]);
                    subkeys.push(subkey_name);
                    index += 1;
                } else if status.0 == 259 {
                    // ERROR_NO_MORE_ITEMS (259)，表示没有更多子键
                    break;
                } else {
                    // 其他错误
                    return Err(Error::from_win32());
                }
            }
        }

        Ok(subkeys)
    }

    pub fn list_values(&self) -> Result<HashMap<String, RegistryValue>> {
        let mut index = 0;
        let mut values = HashMap::new();

        loop {
            let mut name = vec![0u16; 256];
            let mut name_len = name.len() as u32;
            let mut data_type = REG_VALUE_TYPE(0);
            let mut buffer = vec![0u8; 1024]; // 适当设置缓冲区大小
            let mut buffer_size = buffer.len() as u32;

            unsafe {
                let status = RegEnumValueW(
                    self.hkey,
                    index,
                    PWSTR(name.as_mut_ptr()),
                    &mut name_len,
                    Some(null_mut()),
                    Some(&mut data_type.0),
                    Some(buffer.as_mut_ptr()),
                    Some(&mut buffer_size),
                );

                if status.0 == 0 {
                    let value_name = String::from_utf16_lossy(&name[..name_len as usize]);
                    let value_content = RegistryValue::from_buffer(data_type, &buffer, buffer_size);
                    values.insert(value_name, value_content);
                    index += 1;
                } else if status.0 == 259 {
                    break;
                } else {
                    return Err(Error::from_win32());
                }
            }
        }

        Ok(values)
    }
}

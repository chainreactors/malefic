use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, EnumServicesStatusExW, OpenSCManagerW, 
    OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx, StartServiceW, 
    QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_ALL_ACCESS, SC_STATUS_PROCESS_INFO, 
    SERVICE_ALL_ACCESS, SERVICE_CONTROL_STOP, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START, 
    SERVICE_STATE_ALL, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_WIN32_OWN_PROCESS};
use windows::core::{Error, Result, PCWSTR};
use std::ptr::null_mut;
use std::mem::size_of;
use crate::win::common;

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ServiceType {
    OwnProcess,
    SharedProcess,
    Driver,
}

#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ServiceStartType {
    BootStart,
    SystemStart,
    AutoStart,
    DemandStart,
    Disabled,
}

impl ServiceStartType {
    pub fn to_win32(&self) -> windows::Win32::System::Services::SERVICE_START_TYPE {
        match self {
            ServiceStartType::BootStart => windows::Win32::System::Services::SERVICE_BOOT_START,
            ServiceStartType::SystemStart => windows::Win32::System::Services::SERVICE_SYSTEM_START,
            ServiceStartType::AutoStart => windows::Win32::System::Services::SERVICE_AUTO_START,
            ServiceStartType::DemandStart => windows::Win32::System::Services::SERVICE_DEMAND_START,
            ServiceStartType::Disabled => windows::Win32::System::Services::SERVICE_DISABLED,
        }
    }
}
// 服务错误控制
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ServiceErrorControl {
    Ignore,
    Normal,
    Severe,
    Critical,
}

// 服务依赖关系
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ServiceDependency {
    Service(String),
    Group(String),
}

// 服务状态
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
}

// 服务退出代码
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ServiceExitCode {
    Win32(u32),
    ServiceSpecific(u32),
}

// 服务配置结构体
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct ServiceConfig {
    pub name: String,
    pub service_type: ServiceType,
    pub start_type: ServiceStartType,
    pub error_control: ServiceErrorControl,
    pub executable_path: PathBuf,
    pub tag_id: u32,
    pub account_name: Option<OsString>,
    pub display_name: OsString,
}

// 服务状态结构体
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct ServiceStatus {
    pub current_state: ServiceState,
    pub process_id: Option<u32>,
    pub exit_code: ServiceExitCode,
    pub checkpoint: u32,
    pub wait_hint: Duration,
}

// 上层结构体，将 ServiceConfig 和 ServiceStatus 包裹
#[cfg_attr(debug_assertions, derive(Debug))]
#[derive(Clone)]
pub struct Service {
    pub config: ServiceConfig,
    pub status: Option<ServiceStatus>,
}

pub struct ServiceManager {
    scm_handle: SC_HANDLE,
}


// 定义 TokenElevation 为常量

impl ServiceManager {
    // 打开服务管理器
    pub fn open() -> Result<Self> {
        unsafe {
            if crate::common::sysinfo::is_privilege() {
                let scm_handle = OpenSCManagerW(PCWSTR(null_mut()), PCWSTR(null_mut()), SC_MANAGER_ALL_ACCESS)?;
                if scm_handle.is_invalid() {
                    return Err(Error::from_win32());
                }
                return Ok(ServiceManager { scm_handle });
            }

            // 使用有限权限
            let scm_handle = OpenSCManagerW(PCWSTR(null_mut()), PCWSTR(null_mut()), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)?;
            if scm_handle.is_invalid() {
                return Err(Error::from_win32());
            }
            Ok(ServiceManager { scm_handle })
        }
    }

    // 关闭服务管理器
    pub fn close(self) {
        let _ = unsafe { CloseServiceHandle(self.scm_handle) };
    }
    pub fn create_service(
        &self,
        name: &str,
        display_name: &str,
        executable_path: &str,
        start_type: ServiceStartType,
        error_control: ServiceErrorControl,
        account_name: Option<&str>
    ) -> Result<ServiceConfig> {
        let service_name_wide = common::to_wide_string(name);
        let display_name_wide = common::to_wide_string(display_name);
        let executable_path_wide = common::to_wide_string(executable_path);

        let account_name_wide = match account_name {
            Some(account) => common::to_wide_string(account),
            None => common::to_wide_string("LocalSystem"), // 默认使用 LocalSystem 账户
        };

        unsafe {
            let service_handle = CreateServiceW(
                self.scm_handle,
                PCWSTR(service_name_wide.as_ptr()),
                PCWSTR(display_name_wide.as_ptr()),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                start_type.to_win32(),
                match error_control {
                    ServiceErrorControl::Ignore => windows::Win32::System::Services::SERVICE_ERROR_IGNORE,
                    ServiceErrorControl::Normal => windows::Win32::System::Services::SERVICE_ERROR_NORMAL,
                    ServiceErrorControl::Severe => windows::Win32::System::Services::SERVICE_ERROR_SEVERE,
                    ServiceErrorControl::Critical => windows::Win32::System::Services::SERVICE_ERROR_CRITICAL,
                },
                PCWSTR(executable_path_wide.as_ptr()),
                None,   // Load order group (not used)
                None,   // Tag ID
                None,   // Dependencies (not used)
                PCWSTR(account_name_wide.as_ptr()), // Service account name
                None,   // Password (if required)
            )?;

            if service_handle.is_invalid() {
                return Err(Error::from_win32());
            }

            let _ = CloseServiceHandle(service_handle);

            // 返回 `ServiceConfig`
            Ok(ServiceConfig {
                name: name.to_string(),
                service_type: ServiceType::OwnProcess,
                start_type,
                error_control,
                executable_path: PathBuf::from(executable_path),
                tag_id: 0, // Tag ID 这里默认 0
                account_name: Some(OsString::from(account_name.unwrap_or("LocalSystem"))),
                display_name: OsString::from(display_name),
            })
        }
    }

    // 启动服务
    pub fn start_service(&self, config: &ServiceConfig) -> Result<()> {
        let service_name_wide = common::to_wide_string(&config.name);

        unsafe {
            let service_handle = OpenServiceW(self.scm_handle, PCWSTR(service_name_wide.as_ptr()), SERVICE_START)?;
            if service_handle.is_invalid() {
                return Err(Error::from_win32());
            }

            StartServiceW(service_handle, None)?;
            let _ = CloseServiceHandle(service_handle);

            Ok(())
        }
    }

    // 停止服务
    pub fn stop_service(&self, config: &ServiceConfig) -> Result<()> {
        let service_name_wide = common::to_wide_string(&config.name);

        unsafe {
            let service_handle = OpenServiceW(self.scm_handle, PCWSTR(service_name_wide.as_ptr()), SERVICE_STOP)?;
            if service_handle.is_invalid() {
                return Err(Error::from_win32());
            }

            let mut status = SERVICE_STATUS::default();
            ControlService(service_handle, SERVICE_CONTROL_STOP, &mut status)?;
            let _ = CloseServiceHandle(service_handle);

            Ok(())
        }
    }

    // 删除服务
    pub fn delete_service(&self, config: &ServiceConfig) -> Result<()> {
        let service_name_wide = common::to_wide_string(&config.name);

        unsafe {
            let service_handle = OpenServiceW(self.scm_handle, PCWSTR(service_name_wide.as_ptr()), SERVICE_ALL_ACCESS)?;
            if service_handle.is_invalid() {
                return Err(Error::from_win32());
            }

            DeleteService(service_handle)?;
            let _ = CloseServiceHandle(service_handle);
        }
        Ok(())
    }

    pub fn query_service(&self, service_name: &str) -> Result<ServiceConfig> {
        let service_name_wide = common::to_wide_string(service_name);

        unsafe {
            let service_handle = OpenServiceW(self.scm_handle, PCWSTR(service_name_wide.as_ptr()), SERVICE_QUERY_CONFIG)?;
            if service_handle.is_invalid() {
                return Err(Error::from_win32());
            }

            let mut config_size_needed = 0;
            let result = QueryServiceConfigW(service_handle, None, 0, &mut config_size_needed);
            if result.is_ok() || config_size_needed == 0 {
                CloseServiceHandle(service_handle)?;
                return Err(Error::from_win32()); // 如果查询失败或者没有配置，返回错误
            }

            let mut config_buffer = vec![0u8; config_size_needed as usize];
            let service_config: *mut QUERY_SERVICE_CONFIGW = config_buffer.as_mut_ptr() as *mut _;

            let result = QueryServiceConfigW(service_handle, Some(service_config), config_size_needed, &mut config_size_needed);
            if result.is_err() {
                CloseServiceHandle(service_handle)?;
                return Err(result.unwrap_err()); // 返回错误
            }

            let executable_path = common::wide_to_string(PCWSTR((*service_config).lpBinaryPathName.0));
            let account_name = if !(*service_config).lpServiceStartName.is_null() {
                Some(OsString::from(common::wide_to_string(PCWSTR((*service_config).lpServiceStartName.0))))
            } else {
                None
            };

            CloseServiceHandle(service_handle)?;

            Ok(ServiceConfig {
                name: service_name.to_string(),
                service_type: match (*service_config).dwServiceType {
                    windows::Win32::System::Services::SERVICE_WIN32_OWN_PROCESS => ServiceType::OwnProcess,
                    windows::Win32::System::Services::SERVICE_WIN32_SHARE_PROCESS => ServiceType::SharedProcess,
                    _ => ServiceType::Driver, // 其他类型
                },
                start_type: match (*service_config).dwStartType {
                    windows::Win32::System::Services::SERVICE_BOOT_START => ServiceStartType::BootStart,
                    windows::Win32::System::Services::SERVICE_SYSTEM_START => ServiceStartType::SystemStart,
                    windows::Win32::System::Services::SERVICE_AUTO_START => ServiceStartType::AutoStart,
                    windows::Win32::System::Services::SERVICE_DEMAND_START => ServiceStartType::DemandStart,
                    _ => ServiceStartType::Disabled,
                },
                error_control: match (*service_config).dwErrorControl {
                    windows::Win32::System::Services::SERVICE_ERROR_IGNORE => ServiceErrorControl::Ignore,
                    windows::Win32::System::Services::SERVICE_ERROR_NORMAL => ServiceErrorControl::Normal,
                    windows::Win32::System::Services::SERVICE_ERROR_SEVERE => ServiceErrorControl::Severe,
                    windows::Win32::System::Services::SERVICE_ERROR_CRITICAL => ServiceErrorControl::Critical,
                    _ => ServiceErrorControl::Normal, // 默认
                },
                executable_path: PathBuf::from(executable_path),
                tag_id: (*service_config).dwTagId,
                account_name,
                display_name: OsString::from(service_name),
            })
        }
    }

    pub fn list_services(&self) -> Result<Vec<ServiceConfig>> {
        let mut buffer_size_needed = 0;
        let mut service_count = 0;
        let mut resume_handle: u32 = 0;
        let mut services = Vec::new();

        unsafe {
            // 第一次调用 EnumServicesStatusExW 以获取所需的缓冲区大小
            let result = EnumServicesStatusExW(
                self.scm_handle,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_STATE_ALL,
                None,
                &mut buffer_size_needed,
                &mut service_count,
                Some(&mut resume_handle),
                None,
            );

            if result.is_err() {
                let error_code = result.unwrap_err().code();
                if error_code != windows::core::HRESULT::from_win32(windows::Win32::Foundation::ERROR_MORE_DATA.0) {
                    return Err(Error::from_win32());
                }
            }

            // 分配缓冲区
            let mut buffer = vec![0u8; buffer_size_needed as usize];

            // 第二次调用 EnumServicesStatusExW 以获取所有服务的基本信息
            let result = EnumServicesStatusExW(
                self.scm_handle,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_STATE_ALL,
                Some(&mut buffer),
                &mut buffer_size_needed,
                &mut service_count,
                Some(&mut resume_handle),
                None,
            );

            if result.is_err() {
                return Err(result.unwrap_err());
            }

            // 遍历服务，提取服务名称并查询其详细配置信息
            let services_ptr = buffer.as_ptr() as *const windows::Win32::System::Services::ENUM_SERVICE_STATUS_PROCESSW;
            for i in 0..service_count {
                let service_status = services_ptr.add(i as usize).read();

                // 将服务名称转换为 Rust 字符串
                let service_name = common::wide_to_string(PCWSTR(service_status.lpServiceName.0));

                // 使用 query_service_by_name 查询每个服务的配置信息
                if let Ok(service_config) = self.query_service(&service_name) {
                    services.push(service_config);
                }
            }
        }

        Ok(services)
    }


    // 查询服务状态并返回 `ServiceStatus`
    pub fn query_service_status(&self, service: &ServiceConfig) -> Result<ServiceStatus> {
        let service_name_wide = common::to_wide_string(&service.name);

        unsafe {
            let service_handle = OpenServiceW(self.scm_handle, PCWSTR(service_name_wide.as_ptr()), SERVICE_QUERY_STATUS)?;
            if service_handle.is_invalid() {
                return Err(Error::from_win32());
            }

            let mut status = SERVICE_STATUS_PROCESS::default();
            let status_slice = std::slice::from_raw_parts_mut(&mut status as *mut _ as *mut u8, size_of::<SERVICE_STATUS_PROCESS>());

            QueryServiceStatusEx(service_handle, SC_STATUS_PROCESS_INFO, Some(status_slice), &mut (size_of::<SERVICE_STATUS_PROCESS>() as u32))?;

            let _ = CloseServiceHandle(service_handle);

            Ok(ServiceStatus {
                current_state: match status.dwCurrentState.0 {
                    1 => ServiceState::Stopped,
                    2 => ServiceState::StartPending,
                    3 => ServiceState::StopPending,
                    4 => ServiceState::Running,
                    5 => ServiceState::ContinuePending,
                    6 => ServiceState::PausePending,
                    7 => ServiceState::Paused,
                    _ => ServiceState::Stopped,
                },
                process_id: Some(status.dwProcessId),
                exit_code: ServiceExitCode::Win32(status.dwWin32ExitCode),
                checkpoint: status.dwCheckPoint,
                wait_hint: Duration::from_millis(status.dwWaitHint as u64),
            })
        }
    }

    // `list_and_query` API，一次性返回所有服务及其状态
    pub fn list_and_query(&self) -> Result<Vec<Service>> {
        let service_configs = self.list_services()?;
        let mut services = Vec::new();

        for config in service_configs {
            let status = self.query_service_status(&config)?;
            services.push(Service {
                config,
                status: Some(status),
            });
        }

        Ok(services)
    }
    
}



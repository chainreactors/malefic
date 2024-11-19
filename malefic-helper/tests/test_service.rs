use std::ffi::OsString;
use std::path::PathBuf;
use malefic_helper::win::service::{ServiceErrorControl, ServiceManager, ServiceStartType};


#[test]
fn test_create_service() {
    let service_manager = ServiceManager::open().unwrap();

    // 创建服务
    let service_config = service_manager
        .create_service(
            "TestService",
            "Test Service Display",
            "C:\\path\\to\\executable",
            ServiceStartType::AutoStart,
            ServiceErrorControl::Normal,
            Some("LocalSystem"),
        )
        .unwrap();

    assert_eq!(service_config.name, "TestService");
    assert_eq!(service_config.display_name, OsString::from("Test Service Display"));
    assert_eq!(service_config.executable_path, PathBuf::from("C:\\path\\to\\executable"));
    assert_eq!(service_config.start_type, ServiceStartType::AutoStart);
    assert_eq!(service_config.error_control, ServiceErrorControl::Normal);
    assert_eq!(service_config.account_name, Some(OsString::from("LocalSystem")));

    service_manager.close();
}


#[test]
fn test_query_service() {
    let service_manager = ServiceManager::open().unwrap();

    // 尝试查询一个存在的服务
    let service_name = "TestService"; // 确保这个服务已经创建并存在于测试环境中
    let service_config = service_manager.query_service(service_name).unwrap();

    // 验证返回的服务配置信息
    assert_eq!(service_config.name, service_name);
    assert!(service_config.display_name.to_str().is_some());
    assert!(service_config.executable_path.exists()); // 确保可执行路径存在
    assert!(service_config.start_type == ServiceStartType::AutoStart ||
        service_config.start_type == ServiceStartType::DemandStart); // 验证启动类型

    service_manager.close();
}

#[test]
fn test_start_stop_service() {
    let service_manager = ServiceManager::open().unwrap();

    // 首先查询服务，确保存在该服务
    let service_config = service_manager.query_service("TestService").unwrap();

    // 启动服务
    let start_result = service_manager.start_service(&service_config);
    assert!(start_result.is_ok(), "Service failed to start");

    // 停止服务
    let stop_result = service_manager.stop_service(&service_config);
    assert!(stop_result.is_ok(), "Service failed to stop");

    service_manager.close();
}

#[test]
fn test_delete_service() {
    let service_manager = ServiceManager::open().unwrap();

    // 首先查询服务，确保存在该服务
    let service_config = service_manager.query_service("TestService").unwrap();

    // 删除服务
    let delete_result = service_manager.delete_service(&service_config);
    assert!(delete_result.is_ok(), "Service failed to be deleted");

    service_manager.close();
}

#[test]
fn test_list_services() {
    // 尝试打开服务管理器并捕获任何错误
    let service_manager = match ServiceManager::open() {
        Ok(manager) => manager,
        Err(e) => {
            eprintln!("Failed to open ServiceManager: {}", e);
            return; // 直接返回，跳过后续测试
        }
    };

    // 尝试列出服务并捕获结果
    let result = service_manager.list_services();
    match result {
        Ok(services) => {
            assert!(!services.is_empty(), "Service list should not be empty"); // 确保服务列表不为空

            for service in services {
                println!("Service Name: {}", service.name);
                println!("Executable Path: {:?}", service.executable_path);
                println!("Start Type: {:?}", service.start_type);
                println!("Error Control: {:?}", service.error_control);
            }
        }
        Err(e) => {
            eprintln!("Failed to list services: {}", e);
            assert!(false, "Expected to list services but failed with error: {}", e); // 触发失败
        }
    }

    service_manager.close();
}

#[test]
fn test_list_and_query_services() {
    let service_manager = ServiceManager::open().unwrap();
    let result = service_manager.list_and_query();
    assert!(result.is_ok());

    let services = result.unwrap();
    for service in services {
        println!("Service Name: {}", service.config.name);
        if let Some(status) = service.status {
            println!("Service State: {:?}", status.current_state);
        }
    }

    service_manager.close();
}

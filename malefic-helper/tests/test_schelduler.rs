use std::path::PathBuf;
use std::time::Duration;
use malefic_helper::win::scheduler::{TaskConfig, TaskSchedulerManager, TaskTriggerType};

// 测试任务配置信息
fn test_task_config() -> TaskConfig {
    TaskConfig {
        name: "TestTask".to_string(),
        path: "\\".to_string(), // 测试文件夹路径
        description: "A test task for unit testing".to_string(),
        executable_path: PathBuf::from("C:\\Windows\\System32\\notepad.exe"),
        trigger_type: TaskTriggerType::Daily,
        duration: Duration::from_secs(3600),
        start_boundary: "2024-01-01T12:00:00".to_string(),
        enabled: true,
    }
}


#[test]
fn test_create_task() {
    let manager = TaskSchedulerManager::initialize().expect("Initialization failed");
    let config = test_task_config();
    let result = manager.create_task(config.clone());
    println!("Task config: {:?}", result);
    assert!(result.is_ok(), "Failed to create task: {:?}", result);
}

#[test]
fn test_run_task() {
    let manager = TaskSchedulerManager::initialize().expect("Initialization failed");
    let config = test_task_config();

    let result = manager.run_task(&config.path, &config.name);
    assert!(result.is_ok(), "Failed to run task: {:?}", result);
}

#[test]
fn test_start_task() {
    let manager = TaskSchedulerManager::initialize().expect("Initialization failed");
    let config = test_task_config();

    let result = manager.start_task(&config.path, &config.name);
    assert!(result.is_ok(), "Failed to start task: {:?}", result);
}

#[test]
fn test_stop_task() {
    let manager = TaskSchedulerManager::initialize().expect("Initialization failed");
    let config = test_task_config();
    manager.start_task(&config.path, &config.name).expect("Task start failed");

    let result = manager.stop_task(&config.path, &config.name);
    assert!(result.is_ok(), "Failed to stop task: {:?}", result);
}

#[test]
fn test_query_task() {
    let manager = TaskSchedulerManager::initialize().expect("Initialization failed");

    let result = manager.query_task("\\", "TestTask");
    assert!(result.is_ok(), "Failed to query task: {:?}", result);

    if let Ok(status) = result {
        println!("Task status: {:?}", status); 
    }
}

#[test]
fn test_delete_task() {
    let manager = TaskSchedulerManager::initialize().expect("Initialization failed");
    let config = test_task_config();

    let result = manager.delete_task(&config.path, &config.name);
    assert!(result.is_ok(), "Failed to delete task: {:?}", result);

    // Check if the task was deleted successfully by trying to query it
    let query_result = manager.query_task(&config.path, &config.name);
    assert!(query_result.is_err(), "Task should be deleted and no longer queryable");
}

#[test]
fn test_list_tasks() {
    let manager = TaskSchedulerManager::initialize().expect("Initialization failed");

    let result = manager.list_tasks("\\");
    assert!(result.is_ok(), "Failed to list tasks: {:#?}", result);
    println!("Tasks: {:#?}", result);
}
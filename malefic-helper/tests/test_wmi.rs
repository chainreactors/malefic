use std::collections::HashMap;
use wmi::Variant;
use malefic_helper::win::wmi::WmiManager;

#[test]
fn test_execute_query() {
    let manager = WmiManager::open(Some("ROOT\\CIMV2")).expect("Failed to open WMI connection");

    // 执行通用查询，例如查询 Win32_Process 的实例
    let query = "SELECT * FROM meta_class WHERE __CLASS = 'Win32_Process'";
    let results = manager.execute_query(query)
        .unwrap_or_else(|e| panic!("Failed to execute WMI query: {}", e));

    // 打印结果
    println!("Results of SELECT * FROM Win32_Process: {:?}", results);

    // 检查是否返回了至少一个进程实例
    assert!(!results.is_empty(), "No instances found for query Win32_Process");
}

#[test]
fn test_execute_method() {
    let manager = WmiManager::open(Some("ROOT\\CIMV2")).expect("Failed to open WMI connection");

    // 为 Win32_Process.Create 方法构建参数（启动 notepad.exe）
    let mut params = HashMap::new();
    params.insert("CommandLine".to_string(), Variant::String("notepad.exe".to_string()));

    // 执行 Win32_Process 的 Create 方法
    let result = manager.execute_method("Win32_Process", "Create", params);
    println!("Result of Win32_Process.Create: {:?}", result.unwrap());
}
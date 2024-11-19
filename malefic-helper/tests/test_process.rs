use windows::Win32::System::Threading::GetCurrentProcessId;
use malefic_helper::win::process::{get_process_architecture, get_process_owner};
use malefic_helper::win::token::is_privilege;

#[test]
fn test_is_privilege() {
    match is_privilege() {
        Ok(is_elevated) => {
            if is_elevated {
                println!("User is running with elevated privileges.");
            } else {
                println!("User is not running with elevated privileges.");
            }
            assert!(is_elevated == true || is_elevated == false);
        }
        Err(e) => panic!("Failed to check privileges: {:?}", e),
    }
}


#[test]
fn test_get_process_architecture() {
    let pid = unsafe { GetCurrentProcessId() }; // 获取当前进程ID
    match get_process_architecture(pid) {
        Ok(arch) => {
            println!("Process architecture: {}", arch);
            assert!(arch == "x86" || arch == "x64" || arch == "Unknown");
        }
        Err(e) => {
            println!("Failed to get process architecture: {:?}", e);
            assert!(false); // 如果出错，断言失败
        }
    }
}

#[test]
fn test_get_process_owner() {
    let pid = 43932; // 获取当前进程ID
    match get_process_owner(pid) {
        Ok(owner) => {
            println!("Process owner: {}", owner);
            assert!(!owner.is_empty()); // 断言获取到的用户名不是空的
        }
        Err(e) => {
            println!("Failed to get process owner: {:?}", e);
            assert!(false); // 如果出错，断言失败
        }
    }
}
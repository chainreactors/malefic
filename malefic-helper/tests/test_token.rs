use malefic_helper::win::common::to_wide_string;
use malefic_helper::win::process::get_current_pid;
use malefic_helper::win::token::{
    current_token_owner, enable_privilege, get_privs, get_process_integrity_level, has_privilege,
    impersonate_process, lookup_privilege_name_by_luid, make_token, revert_to_self, run_as,
    run_process_as_user,
};
use malefic_helper::win::token::{get_system, get_token};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LUID};
use windows::Win32::Security::{LookupPrivilegeValueW, TOKEN_QUERY};
use windows::Win32::System::Threading::GetCurrentProcessId;

#[test]
fn test_enable_privilege() {
    // 传递 SE_DEBUG_NAME 字符串而不是 PCWSTR
    match enable_privilege("SeDebugPrivilege") {
        Ok(_) => println!("Successfully enabled SeDebugPrivilege."),
        Err(e) => panic!("Failed to enable privilege: {:?}", e),
    }
}

#[test]
fn test_getsystem() {
    let data = b"test data";
    let pid = get_current_pid();
    match get_system() {
        Ok(_) => println!("Successfully got system."),
        Err(e) => panic!("Failed to get system: {:?}", e),
    }
}

#[test]
fn test_impersonate_user() {
    // 使用假设的用户凭据进行模拟测试
    let user_name = "newadmin";
    let domain = "";
    let password = "password123";

    match make_token(user_name, domain, password) {
        Ok(_) => println!("Successfully impersonated user."),
        Err(e) => println!("Failed to impersonate user: {:?}", e),
    }
}

#[test]
fn test_revert_to_self() {
    // 测试恢复到原始用户上下文
    if let Err(e) = revert_to_self() {
        panic!("Failed to revert to self: {:?}", e);
    } else {
        println!("Successfully reverted to self.");
    }
}

#[test]
fn test_impersonate_process() {
    // 使用当前进程的 PID 测试 impersonation
    let pid = 12468;
    match impersonate_process(pid) {
        Ok(handle) => unsafe {
            println!("Successfully impersonated process with PID: {}", pid);
            CloseHandle(handle).unwrap();
        },
        Err(e) => panic!("Failed to impersonate process: {:?}", e),
    }
}

#[test]
fn test_run_process_as_user() {
    let user_name = "newadmin";
    let command = "notepad.exe";
    let args = "";

    match run_process_as_user(user_name, command, args) {
        Ok(_) => println!("Process ran successfully as user: {}", user_name),
        Err(e) => panic!("Failed to run process as user: {:?}", e),
    }
}

#[test]
fn test_get_process_integrity_level() {
    let token_handle = get_token(unsafe { GetCurrentProcessId() }, TOKEN_QUERY).unwrap();
    match get_process_integrity_level(token_handle) {
        Ok(level) => println!("Process integrity level: {}", level),
        Err(e) => panic!("Failed to get process integrity level: {:?}", e),
    }
}

#[test]
fn test_lookup_privilege_name_by_luid() {
    // 使用 SeShutdownPrivilege 作为示例特权名
    let privilege_name = "SeShutdownPrivilege";
    let mut luid = LUID::default();

    unsafe {
        // 先通过 LookupPrivilegeValueW 获取该特权的 LUID
        if LookupPrivilegeValueW(
            None,
            PCWSTR(to_wide_string(privilege_name).as_ptr()),
            &mut luid,
        )
        .is_err()
        {
            panic!("Failed to lookup LUID for privilege: {}", privilege_name);
        }
    }

    // 然后调用 lookup_privilege_name_by_luid 来获取权限名称和显示名称
    match lookup_privilege_name_by_luid(luid) {
        Ok((name, display_name)) => {
            println!("Privilege name: {}, Display name: {}", name, display_name);
        }
        Err(e) => panic!("Failed to lookup privilege name: {:?}", e),
    }
}

#[test]
fn test_get_privs() {
    // 获取并打印当前进程的权限列表
    match get_privs() {
        Ok(privileges) => {
            for (name, display_name) in privileges {
                println!("Privilege: {}, Display Name: {}", name, display_name);
            }
        }
        Err(e) => panic!("Failed to get privileges: {:?}", e),
    }
}

#[test]
fn test_current_token_owner() {
    // 获取当前线程的 token 所属者
    match current_token_owner() {
        Ok(owner) => println!("Current token owner: {}", owner),
        Err(e) => panic!("Failed to get current token owner: {:?}", e),
    }
}

#[test]
fn test_run_as() {
    let username = "hunter";
    let domain = "";
    let password = "zmalqp2112";
    let program = "whoami";
    let args = "";

    // 测试基本运行
    match run_as(
        username, domain, password, program, args, false, false, false,
    ) {
        Ok(output) => println!(
            "Successfully ran process with basic options. Output: {}",
            output
        ),
        Err(e) => println!("Failed to run process with basic options: {:?}", e),
    }

    // 测试网络凭据模式
    match run_as(
        username, domain, password, program, args, true, false, false,
    ) {
        Ok(output) => println!(
            "Successfully ran process with network credentials. Output: {}",
            output
        ),
        Err(e) => println!("Failed to run process with network credentials: {:?}", e),
    }

    // 测试加载用户配置文件
    match run_as(
        username, domain, password, program, args, false, true, false,
    ) {
        Ok(output) => println!(
            "Successfully ran process with user profile. Output: {}",
            output
        ),
        Err(e) => println!("Failed to run process with user profile: {:?}", e),
    }

    // 测试继承环境变量
    match run_as(
        username, domain, password, program, args, false, false, true,
    ) {
        Ok(output) => println!(
            "Successfully ran process with inherited environment. Output: {}",
            output
        ),
        Err(e) => println!("Failed to run process with inherited environment: {:?}", e),
    }

    // 测试组合选项
    match run_as(username, domain, password, program, args, false, true, true) {
        Ok(output) => println!(
            "Successfully ran process with combined options. Output: {}",
            output
        ),
        Err(e) => println!("Failed to run process with combined options: {:?}", e),
    }
}

#[test]
fn test_has_privilege() {
    // 测试一些常见的特权
    let privileges = vec![
        "SeDebugPrivilege",
        "SeShutdownPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
    ];

    for privilege in privileges {
        match has_privilege(privilege) {
            Ok(has_priv) => {
                println!(
                    "Privilege {} status: {}",
                    privilege,
                    if has_priv { "enabled" } else { "disabled" }
                );

                // 如果权限未启用，尝试启用它
                if !has_priv {
                    match enable_privilege(privilege) {
                        Ok(_) => {
                            // 再次检查权限状态
                            match has_privilege(privilege) {
                                Ok(now_has_priv) => {
                                    println!(
                                        "After enabling, privilege {} status: {}",
                                        privilege,
                                        if now_has_priv { "enabled" } else { "disabled" }
                                    );
                                }
                                Err(e) => println!(
                                    "Failed to check privilege status after enabling: {:?}",
                                    e
                                ),
                            }
                        }
                        Err(e) => println!("Failed to enable privilege: {:?}", e),
                    }
                }
            }
            Err(e) => println!("Failed to check privilege {}: {:?}", privilege, e),
        }
    }
}

#[test]
fn test_enable_and_check_privilege() {
    let privilege = "SeDebugPrivilege";

    // 先检查初始状态
    let initial_state = has_privilege(privilege).unwrap_or(false);
    println!(
        "Initial state of {}: {}",
        privilege,
        if initial_state { "enabled" } else { "disabled" }
    );

    // 尝试启用权限
    match enable_privilege(privilege) {
        Ok(_) => {
            println!("Successfully called enable_privilege for {}", privilege);

            // 检查是否真的启用了
            match has_privilege(privilege) {
                Ok(enabled) => {
                    println!(
                        "Privilege {} is now {}",
                        privilege,
                        if enabled { "enabled" } else { "still disabled" }
                    );
                    assert!(
                        enabled,
                        "Privilege should be enabled after enable_privilege call"
                    );
                }
                Err(e) => panic!("Failed to check privilege status: {:?}", e),
            }
        }
        Err(e) => println!("Failed to enable privilege: {:?}", e),
    }
}

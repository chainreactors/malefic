use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LUID};
use windows::Win32::Security::{LookupPrivilegeValueW, TOKEN_QUERY};
use windows::Win32::System::Threading::GetCurrentProcessId;
use malefic_helper::win::common::to_wide_string;
use malefic_helper::win::token::get_token;
use malefic_helper::win::token::{current_token_owner, enable_privilege, get_privs, get_process_integrity_level, impersonate_process, lookup_privilege_name_by_luid, make_token, revert_to_self, run_as, run_process_as_user};

#[test]
fn test_enable_privilege() {
    // 传递 SE_DEBUG_NAME 字符串而不是 PCWSTR
    match enable_privilege("SeDebugPrivilege") {
        Ok(_) => println!("Successfully enabled SeDebugPrivilege."),
        Err(e) => panic!("Failed to enable privilege: {:?}", e),
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
        if LookupPrivilegeValueW(None, PCWSTR(to_wide_string(privilege_name).as_ptr()), &mut luid).is_err() {
            panic!("Failed to lookup LUID for privilege: {}", privilege_name);
        }
    }

    // 然后调用 lookup_privilege_name_by_luid 来获取权限名称和显示名称
    match lookup_privilege_name_by_luid(luid) {
        Ok((name, display_name)) => {
            println!("Privilege name: {}, Display name: {}", name, display_name);
        },
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
        },
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
    let username = "newadmin";
    let domain = "";
    let password = "password123";
    let program = "C:\\Windows\\System32\\notepad.exe";
    let args = "";

    match run_as(username, domain, password, program, args, 5, false) {
        Ok(_) => println!("Successfully ran process as user: {}", username),
        Err(e) => panic!("Failed to run process as user: {:?}", e),
    }
}
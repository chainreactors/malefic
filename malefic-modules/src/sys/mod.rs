#[cfg(debug_assertions)]
pub mod example;
pub mod ps;
pub mod netstat;
pub mod env;
pub mod whoami;
// mod reg;
pub mod kill;
// mod spawn;
pub mod info;

#[cfg(target_family = "windows")]
pub mod bypass;
#[cfg(target_family = "windows")]
pub mod reg;
#[cfg(target_family = "windows")]
pub mod service;
#[cfg(target_family = "windows")]
pub mod taskschd;
#[cfg(target_family = "windows")]
#[cfg(feature = "wmi")]
pub mod wmi;
#[cfg(target_family = "windows")]
pub mod token;
#[cfg(target_family = "windows")]
pub mod inject;


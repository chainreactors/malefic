#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use malefic_autorun::run;

fn main() -> anyhow::Result<()> {
    run()
}

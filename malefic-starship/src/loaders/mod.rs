//! Loader modules (Community Edition)

pub mod common;

#[cfg(feature = "basic_template")]
pub mod basic_template;

#[cfg(feature = "func_ptr")]
pub mod func_ptr;

/// All available loader names
pub const LOADER_NAMES: &[&str] = &[
    "basic_template",
    "func_ptr",
];

/// Get a random loader name
pub fn random_loader() -> &'static str {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as usize;
    LOADER_NAMES[seed % LOADER_NAMES.len()]
}

#![allow(dead_code)]

pub mod apis;
pub mod bof;
#[cfg(feature = "bypass")]
pub mod bypass;
pub mod clr;
pub mod hide;
pub mod inject;
pub mod pe;
pub mod pwsh;

pub mod binding;

/// Subset of winkit's MaleficModule — only the fields consumers actually use.
/// Safe because winkit's full struct is #[repr(C)], so the first 3 fields
/// have identical layout.
#[repr(C)]
pub struct MaleficModule {
    pub new_module: *mut core::ffi::c_void,
    pub entry_point: *const core::ffi::c_void,
    pub export_func: Vec<(String, usize)>,
}

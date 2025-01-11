#[cfg(feature = "Win_Inject_Fiber")]
pub mod fiber;
#[cfg(feature = "Win_Inject_Thread")]
pub mod thread;
#[cfg(feature = "Win_Inject_APC")]
pub mod apc;

#[cfg(feature = "Win_Inject_Fiber")]
compile_error!("Win_Inject_Fiber is deprecated");
#[cfg(feature = "Win_Inject_Thread")]
compile_error!("Win_Inject_Thread is deprecated");

#[cfg(feature = "Win_Inject_APC")]
pub use apc::loader as loader;
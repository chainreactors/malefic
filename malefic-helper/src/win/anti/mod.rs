pub mod sandbox;
pub mod vm;

pub use sandbox::*;
pub use vm::{
    VmFramework, VmDetectionResult,
    detect_vm_framework, is_vm_environment, get_vm_framework_name,
    // Legacy compatibility functions
    is_running_in_vm, get_detected_vm_type
}; 
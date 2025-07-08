//! Virtual Machine Detection Module
//!
//! This module provides precise VM framework detection capabilities using framework-specific
//! signatures and indicators. The detection prioritizes CPUID hypervisor detection to avoid
//! false positives on host machines with VM software installed.
//!
//! ## Key Design Principles
//!
//! 1. **CPUID First**: Primary detection relies on CPUID hypervisor bit (ECX bit 31 of leaf 1)
//! 2. **No Host Artifacts**: Avoids checking VM software installation artifacts on host machines
//! 3. **Framework Specific**: Identifies specific VM technologies via hypervisor vendor strings
//! 4. **Fallback Detection**: Uses CPU timing analysis only when CPUID detection fails
//!
//! ## Supported VM Frameworks
//!
//! - **VirtualBox**: Oracle VM VirtualBox (`VBoxVBoxVBox`)
//! - **VMware**: VMware Workstation/ESXi (`VMwareVMware`)  
//! - **Hyper-V**: Microsoft Hyper-V (`Microsoft Hv`)
//! - **QEMU**: QEMU/KVM (`TCGTCGTCGTCG`)
//! - **Xen**: Citrix Xen hypervisor (`XenVMMXenVMM`)
//! - **Unknown**: Detected via timing analysis or unknown hypervisor

use obfstr::obfstr;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use std::arch::x86_64::{CpuidResult, __cpuid, _rdtsc};

/// Enumeration of supported VM frameworks
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmFramework {
    VirtualBox,
    VMware,
    HyperV,
    QEMU,
    Xen,
    Unknown,
}

impl VmFramework {
    pub fn name(&self) -> &'static str {
        match self {
            VmFramework::VirtualBox => "VirtualBox",
            VmFramework::VMware => "VMware",
            VmFramework::HyperV => "Hyper-V",
            VmFramework::QEMU => "QEMU",
            VmFramework::Xen => "Xen",
            VmFramework::Unknown => "Unknown VM",
        }
    }
}

/// Detailed VM detection result
#[derive(Debug, Clone)]
pub struct VmDetectionResult {
    pub framework: Option<VmFramework>,
    pub detected_features: Vec<String>,
    pub is_vm: bool,
}

impl VmDetectionResult {
    pub fn new() -> Self {
        Self {
            framework: None,
            detected_features: Vec::new(),
            is_vm: false,
        }
    }

    pub fn detected(framework: VmFramework, features: Vec<String>) -> Self {
        Self {
            framework: Some(framework),
            detected_features: features,
            is_vm: true,
        }
    }
}

/// Get CPUID hypervisor vendor string - 最可靠的VM检测方法
/// 
/// 这个函数检查CPUID leaf 1的ECX bit 31 (hypervisor位)
/// 只有在真正的VM环境中这个位才会被设置
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn get_hypervisor_vendor() -> Option<String> {
    unsafe {
        let cpuid_1 = __cpuid(1);
        // 检查hypervisor位 (ECX bit 31)
        if (cpuid_1.ecx & (1 << 31)) == 0 {
            return None; // 没有hypervisor，绝对不是VM
        }

        // 获取hypervisor vendor字符串
        let cpuid_result = __cpuid(0x40000000);
        let vendor_bytes = [
            cpuid_result.ebx.to_le_bytes(),
            cpuid_result.ecx.to_le_bytes(), 
            cpuid_result.edx.to_le_bytes(),
        ].concat();
        
        Some(String::from_utf8_lossy(&vendor_bytes).trim_end_matches('\0').to_string())
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn get_hypervisor_vendor() -> Option<String> {
    None
}

/// Perform CPU timing-based VM detection using the proven inside-vm algorithm
/// 
/// 这个方法测量CPUID指令的执行时间，在VM中通常会比物理机慢
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn detect_vm_by_timing() -> Option<Vec<String>> {
    // Compute cpuid cpu cycles average
    let mut tsc1: u64;
    let mut tsc2: u64;
    let mut cycles: Vec<u64> = vec![];
    let mut cpuid = CpuidResult { eax: 0, ebx: 0, ecx: 0, edx: 0 };
    
    // Perform measurements with outlier removal
    let (low, samples, high) = (5, 100, 5);
    for _ in 0..(low + samples + high) {
        unsafe {
            tsc1 = _rdtsc();
            cpuid = __cpuid(0);
            tsc2 = _rdtsc();
        }
        cycles.push(tsc2 - tsc1);
    }
    
    unsafe {
        // Prevent compiler optimization
        std::ptr::read_volatile(&cpuid);
    }

    // Remove outliers and compute average
    cycles.sort_unstable();
    let cycles_without_outliers = &cycles[low..low + samples];
    let avg = cycles_without_outliers.iter().sum::<u64>() / std::cmp::max(samples as u64, 1);

    // VM detection threshold
    if avg > 1000 {
        Some(vec![format!("CPU timing anomaly detected: {} cycles (threshold: 1000)", avg)])
    } else {
        None
    }
}

/// CPU timing detection fallback for non-x86 architectures
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn detect_vm_by_timing() -> Option<Vec<String>> {
    None
}

/// 严格的VM检测：只依赖CPUID hypervisor检测
/// 
/// 这是避免宿主机误报的最可靠方法。只有在CPU真正运行在hypervisor下时
/// CPUID指令才会报告hypervisor的存在。
pub fn detect_vm_framework() -> VmDetectionResult {
    // 步骤1：检查是否存在hypervisor (最可靠的方法)
    if let Some(vendor) = get_hypervisor_vendor() {
        let mut features = vec![format!("Hypervisor detected via CPUID: {}", vendor)];
        
        // 步骤2：根据vendor字符串确定具体的VM框架
        if vendor.contains("VBoxVBoxVBox") {
            features.push(obfstr!("VirtualBox hypervisor signature").to_string());
            return VmDetectionResult::detected(VmFramework::VirtualBox, features);
        } else if vendor.contains("VMwareVMware") {
            features.push(obfstr!("VMware hypervisor signature").to_string());
            return VmDetectionResult::detected(VmFramework::VMware, features);
        } else if vendor.contains("Microsoft Hv") {
            features.push(obfstr!("Hyper-V hypervisor signature").to_string());
            return VmDetectionResult::detected(VmFramework::HyperV, features);
        } else if vendor.contains("TCGTCGTCGTCG") {
            features.push(obfstr!("QEMU hypervisor signature").to_string());
            return VmDetectionResult::detected(VmFramework::QEMU, features);
        } else if vendor.contains("XenVMMXenVMM") {
            features.push(obfstr!("Xen hypervisor signature").to_string());
            return VmDetectionResult::detected(VmFramework::Xen, features);
        } else {
            // 检测到hypervisor但不是已知的框架
            features.push(format!("Unknown hypervisor: {}", vendor));
            return VmDetectionResult::detected(VmFramework::Unknown, features);
        }
    }
    
    // 步骤3：如果没有检测到hypervisor，尝试CPU时序检测作为最后手段
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if let Some(timing_features) = detect_vm_by_timing() {
            return VmDetectionResult::detected(VmFramework::Unknown, timing_features);
        }
    }
    
    // 步骤4：没有检测到任何VM特征
    VmDetectionResult::new()
}

/// Simple check if running in any VM environment
pub fn is_vm_environment() -> bool {
    detect_vm_framework().is_vm
}

/// Get the specific VM framework name if detected
pub fn get_vm_framework_name() -> Option<String> {
    let result = detect_vm_framework();
    result.framework.map(|f| f.name().to_string())
}

/// Get detailed VM detection information
pub fn get_vm_detection_details() -> VmDetectionResult {
    detect_vm_framework()
}

/// Legacy compatibility function - returns true if running in VM
pub fn is_running_in_vm() -> bool {
    is_vm_environment()
}

/// Legacy compatibility function - returns detected VM type
pub fn get_detected_vm_type() -> Option<String> {
    get_vm_framework_name()
} 
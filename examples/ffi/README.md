# Malefic-Win-Kit FFI Interface

## Project Overview

This is a multi-language infrastructure for Windows offensive operations.

Complex low-level Windows capabilities (process injection, in-memory execution, reflective loading, etc.) are encapsulated into ready-to-use APIs and exported as a DLL through standard C ABI. This allows developers using any programming language (C/C++, Go, Rust, Python, C#, Java, Node.js, etc.) to directly leverage these capabilities without reimplementing low-level details.

**Write once, use everywhere. Focus on business logic while the infrastructure handles low-level operations.**

---

## API Reference

Based on `malefic-win-kit.h`, covering common offensive operations:

### PE Loading & Execution

| API | Description |
|-----|-------------|
| **RunPE** | Process hollowing injection, supports argument passing, PID specification, DLL blocking, output capture |
| **InlinePE** | Execute PE inline in current process, supports EXE/DLL, Magic/Signature modification, timeout control |
| **PELoader** | Low-level PE loader, manually map PE to memory, supports signature modification |
| **UnloadPE** | Unload loaded PE modules |
| **RunSacrifice** | Create sacrificial process with command-line hijacking, supports PPID spoofing, DLL blocking |
| **HijackCommandLine** | Hijack current process command-line arguments |

### Reflective Loading

| API | Description |
|-----|-------------|
| **ReflectiveLoader** | Reflective DLL loader, supports custom export functions, sacrificial process, PPID spoofing |
| **MaleficLoadLibrary** | Custom LoadLibrary implementation, supports loading DLL from memory |

### Code Injection

| API | Description |
|-----|-------------|
| **ApcLoaderInline** | Inline APC injection (Early Bird), execute shellcode in current process |
| **ApcLoaderSacriface** | Sacrificial process APC injection, execute shellcode via APC after creating new process |
| **InjectRemoteThread** | Classic remote thread injection, inject shellcode into target process |

### Advanced Execution

| API | Description |
|-----|-------------|
| **MaleficBofLoader** | Beacon Object File (BOF) loader, execute Cobalt Strike BOFs |
| **MaleficExecAssembleInMemory** | .NET Assembly in-memory execution, load managed assemblies without touching disk |
| **MaleficPwshExecCommand** | PowerShell in-memory execution, execute PowerShell commands via CLR hosting |

### Utility Functions

| API | Description |
|-----|-------------|
| **MaleficGetFuncAddrWithModuleBaseDefault** | Get function address from module base (manual GetProcAddress) |
| **SafeFreePipeData** | Safely free Rust-allocated memory (must use this to free returned RawString) |

---

## Language Support

Any language with FFI capability is supported.

Example implementations are provided for several common languages:

| Language | Directory | Use Case |
|----------|-----------|----------|
| **C** | `c/` | Minimal overhead, ideal for C/C++ project integration |
| **Go** | `go/` | High performance, single-file deployment, suitable for cross-platform tools |
| **Rust** | `rust/` | Memory safety, ideal for stability-critical projects |
| **Python** | `python/` | Rapid development, convenient for scripting tools |
| **C#** | `csharp/` | Windows native, commonly used in enterprise environments |

These examples represent a subset of supported languages. **Any language with FFI support can interface with these APIs**:

- **C++** - Same calling convention as C
- **Java** - Via JNA or JNI
- **Node.js** - Using node-ffi-napi
- **Ruby** - Using Fiddle or FFI gem
- **Lua** - LuaJIT FFI library
- **Others** - Nim, Zig, D, Swift, Delphi, and any language supporting C interoperability

---

## Core Principles

The calling flow is consistent across all languages:

1. **Load DLL** - Dynamically load `malefic_win_kit.dll` at runtime
2. **Resolve Functions** - Obtain function addresses by export names
3. **Declare Signatures** - Define function signatures in your language based on `malefic-win-kit.h`
4. **Invoke** - Call the functions following standard C calling convention (cdecl)
5. **Memory Management** - Use `SafeFreePipeData` to release allocated memory

### RawString Structure

APIs returning string or binary data use this structure:

```c
typedef struct {
    uint8_t *data;      // Data pointer
    uintptr_t len;      // Data length
    uintptr_t capacity; // Capacity (internal use)
} RawString;
```

**Important:** `SafeFreePipeData(result.data)` must be called after use to prevent memory leaks.

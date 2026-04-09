# malefic-loader

跨平台运行时代码注入与 shellcode 执行框架。

## 功能简介

- **Shellcode 注入执行**：支持多种注入技术，通过 feature 切换注入方式
- **内存管理**：提供 `MaleficChunk` 内存块抽象，统一分配、权限设置与释放操作
- **热加载模块**：运行时动态加载 PE/DLL 模块并解析导出函数
- **跨平台支持**：Windows 与 Linux 各自提供平台原生注入实现

## 平台支持

### Windows

| 注入方式 | 说明 |
|----------|------|
| APC (默认) | 基于 APC 队列的 shellcode 注入，支持 inline 与 sacrifice 进程两种模式 |
| Fiber | 基于纤程 (Fiber) 的 shellcode 执行（已弃用） |
| Thread | 基于 CreateThread 的 shellcode 执行（已弃用） |

APC 模式下支持父进程欺骗 (`ppid`)、DLL 阻断 (`block_dll`)、输出捕获等高级选项。

### Linux

| 注入方式 | 说明 |
|----------|------|
| memfd (默认) | 通过 `memfd_create` + `fexecve` 在内存中执行 ELF |
| pthread | 通过 `pthread_create` 执行 shellcode |
| spawn | 通过 `std::thread::spawn` 执行 shellcode |

## Features

| Feature | 说明 |
|---------|------|
| `source` | 源码编译模式（默认启用） |
| `prebuild` | 预编译模式 |
| `Win_Inject_APC` | Windows APC 注入（默认启用） |
| `Win_Inject_Fiber` | Windows Fiber 注入（已弃用） |
| `Win_Inject_Thread` | Windows Thread 注入（已弃用） |

## 基本用法

### Shellcode 执行 (Windows APC)

```rust
use malefic_loader::win::loader;

unsafe {
    let shellcode: Vec<u8> = vec![/* shellcode bytes */];
    let result = loader(
        shellcode,
        false,               // is_need_sacrifice
        std::ptr::null_mut(), // sacrifice_commandline
        0,                    // ppid
        false,                // block_dll
        true,                 // need_output
        1,                    // loader_type: 1=InlineRX, 2=InlineRWX
    );
}
```

### 内存中执行 ELF (Linux memfd)

```rust
use malefic_loader::linux::loader;

unsafe {
    let elf_bytes: Vec<u8> = std::fs::read("target_elf").unwrap();
    let output = loader(elf_bytes, true);
}
```

### 热加载 PE 模块 (Windows)

```rust
use malefic_loader::hot_modules::{load_module, get_function_address};

unsafe {
    let dll_bytes: Vec<u8> = std::fs::read("module.dll").unwrap();
    let module = load_module(dll_bytes, "module_name".to_string()).unwrap();
    let func = get_function_address(module, "exported_func");
}
```

### 内存管理

```rust
use malefic_loader::memory::{MaleficMemManager, malloc_and_set_memory};

let mut mgr = MaleficMemManager::default();
unsafe {
    let id = mgr.alloc(4096).unwrap();
    // 使用内存...
    mgr.remove(id).unwrap();
}
```

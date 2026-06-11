# Malefic Starship

模块化 shellcode loader 框架。

```
Load → Decode → Evade → Execute
```

所有组件通过 Cargo feature 门控，只有启用的部分会编译进最终二进制。

> 详细文档见 [docs/opsec/starship.md](../docs/opsec/starship.md)

## 快速开始

```bash
# 基础 loader
cargo build --features func_ptr

# 加密 payload + 规避
cargo build --features sifu_syscall,enc_aes,evader_full

# 内嵌 payload + 全混淆
cargo build --features func_ptr,embedded_payload,obf_full

# 全家桶
cargo build --features sifu_syscall,enc_aes,evader_full,obf_full
```

## Features

### 构建模式

| Feature | 说明 |
|---------|------|
| `source`（默认） | 从源码编译 FFI 绑定 |
| `prebuild` | 链接预编译库 |
| `embedded_payload` | 编译时内嵌 payload |
| `debug` | 启用调试输出 |

### Loader（64 种）

| 类别 | Features |
|------|----------|
| 自注入 | `func_ptr` `basic_template` `fiber_exec` `atexit_callback` `tls_callback` `threadpool_work` |
| Syscall | `direct_syscall` `indirect_syscall` `halos_gate` `ninja_syscall` `sifu_syscall` `sifu_syscall_v2` `sifu_cityhash` `indirect_syscall_halo_stack` `edr_sps_v1` `edr_sps_v2_halo` |
| 远程注入 | `userland_api` `nt_api_remote` `nt_api_dynamic` `remote_mockingjay` `remote_thread_self` `thread_hijack` `woodpecker` |
| APC | `apc_nttestalert` `apc_write` `apc_protect` `apc_ex2` `apc_dll_overload` `apc_dll_overload_peb` `apc_dll_overload_v2` `threadless_apc` `phantom_dll_apc` |
| DLL | `dll_overload` `dll_overload_apc` `dll_entrypoint_hijack` `dll_notification` `phantom_dll_indirect` |
| 回调 | `enum_fonts` `list_planting` `uuid_enum_locales` `mac_enum_locales` `callback_final` |
| VEH/异常 | `veh_rop` `veh_vch` `veh_debug_reg` `veh_indirect_syscall` `exception_debug` `hwbp_exec` `hwbp_xor` |
| Hook | `rtl_thread_hook` `rop_trampoline` `jump_code_peb` `vmt_hook` `vmt_trampoline` `vt_ptr_redirect` `rc4_variant` |
| PoolParty | `pool_party_v1_worker_factory` `pool_party_v2_tp_work` `pool_party_v3_tp_wait` `pool_party_v4_tp_io` `pool_party_v5_tp_alpc` `pool_party_v6_tp_job` `pool_party_v7_tp_direct` `pool_party_v8_tp_timer` |

#### PoolParty 线程池注入 (V1-V8)

基于 [PoolParty](https://github.com/SafeBreach-Labs/PoolParty)（Black Hat EU 2023）的 8 种 Windows 线程池注入技术，通过操纵目标进程的线程池内部结构实现 shellcode 执行。所有变体均为远程注入，需要指定目标 PID。

```bash
# 编译单个变体
cargo build --features pool_party_v7_tp_direct,source --release

# 执行（参数: shellcode文件 目标PID）
./target/release/starship.exe shellcode.bin 1234
```

| Variant | 技术 | 触发方式 |
|---------|------|----------|
| V1 | Worker Factory StartRoutine 覆写 | NtSetInformationWorkerFactory 增加 ThreadMinimum |
| V2 | 远程 TP_WORK 插入 | 修改目标 TaskQueue 链表 |
| V3 | 远程 TP_WAIT 插入 | CreateEvent + NtAssociateWaitCompletionPacket + SetEvent |
| V4 | 远程 TP_IO 插入 | NtSetInformationFile + 重叠 WriteFile |
| V5 | 远程 TP_ALPC 插入 | NtAlpcCreatePort + NtAlpcConnectPort |
| V6 | 远程 TP_JOB 插入 | CreateJobObject + AssignProcessToJobObject |
| V7 | 远程 TP_DIRECT 插入 | ZwSetIoCompletion 直接投递 |
| V8 | 远程 TP_TIMER 插入 | 修改 TimerQueue + NtSetTimer2 |

> V8 的 `POOL_TIMER_QUEUE_OFFSET` 在 Windows 11 24H2 上为 0x70，与旧版本不同。

### 编码（12 种）

`enc_xor` `enc_rc4` `enc_aes` `enc_aes2` `enc_des` `enc_chacha` `enc_base64` `enc_base45` `enc_base58` `enc_uuid` `enc_mac` `enc_ipv4`

### 规避（8 种）

`evader_anti_emu` `evader_god_speed` `evader_api_untangle` `evader_etw_pass` `evader_cfg_patch` `evader_normal_api` `evader_sleep_encrypt` `evader_anti_forensic`

`evader_full` 启用全部。

### 混淆（4 种）

`obf_strings` `obf_junk` `obf_memory` `obf_flow`

`obf_full` = `obf_strings` + `obf_junk` + `obf_memory`

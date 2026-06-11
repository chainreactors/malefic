/**
 * ABI bridge for TinyGo DLL → MSVC Rust.
 *
 * Problem: TinyGo returns multi-value (ptr, int32) in RAX+EDX (register pair),
 * but MSVC expects 16-byte structs via hidden pointer. This bridge resolves the
 * symbols via GetProcAddress and uses out-parameters to avoid struct returns.
 *
 * Compile: cl /c /O2 rem_bridge.c
 *          lib rem_bridge.obj /OUT:rem_bridge.lib
 */
#ifdef _MSC_VER
#include <windows.h>
#include <stdint.h>

static HMODULE g_dll = NULL;

/* Function pointer types — all use simple return types to avoid ABI issues */
typedef int32_t (*SimpleIntFn)(void);
typedef void    (*SimpleVoidFn)(void);
typedef void    (*FreeFn)(void*);

/* For multi-return functions, we call via raw asm to extract RAX+RDX */

static SimpleIntFn   g_rem_init = NULL;
static SimpleIntFn   g_init_dialer = NULL;
static void*         g_rem_dial = NULL;     /* raw pointer — called via asm */
static void*         g_memory_dial = NULL;
static void*         g_memory_read = NULL;
static void*         g_memory_write = NULL;
static void*         g_memory_close_fn = NULL;
static SimpleVoidFn  g_cleanup_agent = NULL;
static FreeFn        g_free_cstring = NULL;

int bridge_load(const char *dll_path) {
    g_dll = LoadLibraryA(dll_path);
    if (!g_dll) return -1;

    g_rem_init      = (SimpleIntFn)GetProcAddress(g_dll, "RemInit");
    g_init_dialer   = (SimpleIntFn)GetProcAddress(g_dll, "InitDialer");
    g_rem_dial      = (void*)GetProcAddress(g_dll, "RemDial");
    g_memory_dial   = (void*)GetProcAddress(g_dll, "MemoryDial");
    g_memory_read   = (void*)GetProcAddress(g_dll, "MemoryRead");
    g_memory_write  = (void*)GetProcAddress(g_dll, "MemoryWrite");
    g_memory_close_fn = (void*)GetProcAddress(g_dll, "MemoryClose");
    g_cleanup_agent = (SimpleVoidFn)GetProcAddress(g_dll, "CleanupAgent");
    g_free_cstring  = (FreeFn)GetProcAddress(g_dll, "FreeCString");

    if (!g_rem_init || !g_rem_dial || !g_memory_read || !g_memory_write || !g_memory_close_fn)
        return -2;

    return g_rem_init();
}

int bridge_init_dialer(void) {
    return g_init_dialer ? g_init_dialer() : -1;
}

/*
 * TinyGo RemDial returns (*byte, int32) in (RAX, EDX).
 * We call it and extract both registers manually.
 */
int bridge_rem_dial(const char *cmdline, void **out_ptr) {
    if (!g_rem_dial) return -1;

    void *fn = g_rem_dial;
    void *ret_ptr;
    int32_t ret_err;

    /* Windows x64: arg1 in RCX, returns in RAX+EDX */
    /* Use a helper: cast to a function returning uint64_t.
     * RAX gets the ptr. We lose EDX... unless we use __int128 or asm.
     *
     * Alternative: cast to a function returning a LARGE_INTEGER (64-bit)
     * for the ptr, and get error from a separate call.
     *
     * Simplest approach that works: call as returning __int64,
     * then EDX is the high 32 bits if we cast to __int128.
     * MSVC doesn't have __int128, so we use intrinsics.
     */

    /* Cast to function returning just the pointer (RAX only) */
    typedef void* (*RawFn)(const char*);
    ret_ptr = ((RawFn)fn)(cmdline);

    /* The error code was in EDX. After the call, EDX is clobbered by
     * the function's epilogue. We can't reliably read it from C.
     *
     * Workaround: if ptr is NULL, treat as error (we don't know the code).
     * If ptr is non-NULL, treat as success.
     */
    if (out_ptr) *out_ptr = ret_ptr;

    /* Heuristic: TinyGo sets ptr=NULL on error, non-NULL on success */
    return (ret_ptr == NULL) ? 3 : 0;  /* 3 = ERR_PREPARE_FAILED as generic */
}

/* IntPairResult {val, err} = 8 bytes total → returned in RAX by MSVC AND TinyGo */
typedef int64_t (*IntPairFn1)(const char*, const char*);
typedef int64_t (*IntPairFn3)(int32_t, void*, int32_t);
typedef int32_t (*IntFn1)(int32_t);

int bridge_memory_dial(const char *memhandle, const char *dst, int *out_val) {
    if (!g_memory_dial) return -1;
    int64_t raw = ((IntPairFn1)g_memory_dial)(memhandle, dst);
    int32_t val = (int32_t)(raw & 0xFFFFFFFF);
    int32_t err = (int32_t)((raw >> 32) & 0xFFFFFFFF);
    if (out_val) *out_val = val;
    return err;
}

int bridge_memory_read(int handle, void *buf, int size, int *out_n) {
    if (!g_memory_read) return -1;
    int64_t raw = ((IntPairFn3)g_memory_read)(handle, buf, size);
    int32_t val = (int32_t)(raw & 0xFFFFFFFF);
    int32_t err = (int32_t)((raw >> 32) & 0xFFFFFFFF);
    if (out_n) *out_n = val;
    return err;
}

int bridge_memory_write(int handle, const void *buf, int size, int *out_n) {
    if (!g_memory_write) return -1;
    int64_t raw = ((IntPairFn3)g_memory_write)(handle, (void*)buf, size);
    int32_t val = (int32_t)(raw & 0xFFFFFFFF);
    int32_t err = (int32_t)((raw >> 32) & 0xFFFFFFFF);
    if (out_n) *out_n = val;
    return err;
}

int bridge_memory_close(int handle) {
    return g_memory_close_fn ? ((IntFn1)g_memory_close_fn)(handle) : -1;
}

void bridge_cleanup(void) {
    if (g_cleanup_agent) g_cleanup_agent();
}

void bridge_cleanup_agent(void) {
    bridge_cleanup();
}

void bridge_free_cstring(void *ptr) {
    if (g_free_cstring) g_free_cstring(ptr);
}

#endif /* _MSC_VER */

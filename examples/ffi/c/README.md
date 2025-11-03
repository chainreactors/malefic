# C 调用示例

通过 C 调用 WinKit 高级 API（RunPE、BOF、Reflective DLL 等）。

## 编译运行

```bash
gcc runpe_test.c -o test.exe
./test.exe ../gogo.exe
```

## 自定义

传递参数：
```c
const char *args = "--help";
// 在调用中传递 args
```

注入到进程：
```c
uint32_t pid = 1234;
// 在调用中传递 pid
```

**详细说明见代码注释。**

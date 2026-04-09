# C# 调用示例

通过 C# 调用 WinKit 高级 API（RunPE、BOF、Reflective DLL 等）。

## 编译运行

```bash
csc -unsafe RunPETest.cs
./RunPETest.exe ../gogo.exe
```

要求：Visual Studio 或 .NET SDK

## 自定义

传递参数：
```csharp
byte[] args = Encoding.ASCII.GetBytes("--help");
// 在调用中传递 args
```

使用封装类：
```csharp
using (var kit = new WinKit()) {
    string output = kit.ExecutePE(sacrifice, peData, args: "--help");
}
```

**详细说明见代码注释。**

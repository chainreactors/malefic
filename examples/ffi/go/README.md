# Go 调用示例

通过 Go 调用 WinKit 高级 API（RunPE、BOF、Reflective DLL 等）。

## 运行

```bash
go run runpe_example.go
```

## 自定义

传递参数：
```go
args := []byte("--help")
// 在调用中传递 args
```

注入到进程：
```go
pid := uint32(1234)
// 在调用中传递 pid
```

**详细说明见代码注释。**

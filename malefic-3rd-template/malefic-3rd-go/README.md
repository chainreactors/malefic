# malefic-3rd-go

Go 语言模块，通过 cgo `c-archive` 编译为静态库后链接到 Rust。支持简单请求-响应和双向流式两种模式。

## 前置要求

- Go 1.21+
- `CGO_ENABLED=1`（build.rs 自动设置）

## 目录结构

```
malefic-3rd-go/
├── Cargo.toml
├── build.rs                  # go build -buildmode=c-archive
└── src/
    ├── lib.rs                # Rust 侧 FFI 桥接 + 流式 run()
    └── go/
        ├── go.mod
        ├── main.go           # FFI 导出 + session 管理
        ├── malefic/
        │   ├── module.go     # GoModule / GoModuleHandler 接口
        │   ├── module.proto
        │   └── module.pb.go  # protobuf 生成代码
        └── example/
            └── example.go    # 示例模块
```

## 架构

Rust 和 Go 之间通过双向流式 FFI 通信：

```
Rust async                          Go goroutine
─────────                          ─────────────
Input channel ──GoModuleSend()──→  input chan
                                       ↓
                                   module.Run()
                                       ↓
recv thread   ←─GoModuleRecv()───  output chan
    ↓
futures::select! ──→ Output/return
```

## 两层接口

```go
// GoModuleHandler — 简单模块，无需接触 channel
type GoModuleHandler interface {
    Name() string
    Handle(taskId uint32, req *Request) (*Response, error)
}

// GoModule — 底层流式接口，支持多响应/长任务
type GoModule interface {
    Name() string
    Run(taskId uint32, input <-chan *Request, output chan<- *Response)
}
```

`malefic.AsModule(handler)` 可将 `GoModuleHandler` 包装为 `GoModule`。

## 编写模块

### 简单模块（GoModuleHandler）

```go
package yourmod

import "malefic-3rd-go/malefic"

type Module struct{}

func (m *Module) Name() string { return "your_module" }

func (m *Module) Handle(taskId uint32, req *malefic.Request) (*malefic.Response, error) {
    return &malefic.Response{
        Output: "hello, input: " + req.Input,
    }, nil
}
```

### 流式模块（GoModule）

```go
package yourmod

import "malefic-3rd-go/malefic"

type Module struct{}

func (m *Module) Name() string { return "your_module" }

func (m *Module) Run(taskId uint32, input <-chan *malefic.Request, output chan<- *malefic.Response) {
    for req := range input {
        // 可以发送多个响应
        output <- &malefic.Response{Output: "processing: " + req.Input}
    }
}
```

### 注册模块

编辑 `main.go` 中的 `module` 变量：

```go
var module malefic.GoModule = malefic.AsModule(&yourmod.Module{})   // 简单模块
var module malefic.GoModule = &yourmod.Module{}                     // 流式模块
```

## 添加 Go 依赖

```bash
cd malefic-3rd-go/src/go
go get github.com/some/package
```

## 构建

```bash
cargo build --target x86_64-pc-windows-gnu --no-default-features \
  --features "as_cdylib,golang_module" --release
```

# implant

# Usage
项目采用[cargo make](https://github.com/sagiegurari/cargo-make)来管理编译任务，所以编译任务都在`Makefile.toml`中定义.
使用完整功能请先安装cargo make和docker环境。
## install cargo make
```bash
cargo install --force cargo-make
```
## 本地编译
由于local编译一般不能支持所有平台，所以只写了单个build的编译任务，如果需要多平台交叉请使用`docker`编译.

如下命令会在本地执行编译任务，编译完成后会在`target`目录下生成对应的可执行文件。
```bash
任务名称做了兼容既可以用短名称也可使用target原值
```bash
# 如下两个命令等价
cargo make local windows-x64-gnu
cargo make local x86_64-pc-windows-gnu
# 如下两个命令等价
cargo make local windows-x64-msvc
cargo make local x86_64-pc-windows-msvc
```

## docker编译
如下命令会在docker中执行编译任务，因为使用了volume来挂载源码，所以编译完成后依然会在`target`目录下生成对应的可执行文件。
### 单target编译
```bash
cargo make docker windows-x64-gnu
cargo make docker x86_64-pc-windows-gnu
```
### 多target编译
参考如下命令, 通过空格分隔多个target，你依然可以使用短名称
```bash
cargo make docker windows-x64-gnu windows-x64-msvc windows-x32-gnu linux-x64-gnu linux-x32-gnu
```

### 所有以支持的target
```bash
cargo make docker all
```

> Tmp record

### Stager

#### Stage0

使用 `Stage0`, 可以使用 `malefic-mutant` 来进行代码生成操作， 具体操作如下:

1. generate code
```bash
cargo run -p malefic-mutant stage0 professional x86_64 source
```

2. generate exe && code
```bash
cargo build --profile release-lto -p malefic-pulse
```

```bash
objcopy -O binary ./target/release/malefic-pulse.exe malefic-pulse.bin
```
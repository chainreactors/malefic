# malefic-3rd

## wasmloader

The optional `wasmloader` feature registers a `wasmloader` module that executes
WASI-compatible WebAssembly bytecode with the `wasmi` interpreter. It also
implements the `wasix_32v1` IPv4 TCP socket imports emitted by the REM TinyGo
build.

The interpreter dependencies are feature-gated: default `full` builds include
them, while minimal builds can omit the entire WASM runtime.

The module accepts an `ExecuteBinary` request:

| Field | Meaning |
| --- | --- |
| `bin` | WebAssembly bytecode |
| `entry_point` | Exported no-argument function; defaults to `_start` |
| `name` | WASI `argv[0]`; defaults to `wasmloader` |
| `args` | Remaining WASI arguments |
| `param` | WASI environment variables and the reserved limits below |
| `data` | Standard input |

Reserved `param` keys:

| Key | Default | Maximum |
| --- | ---: | ---: |
| `fuel` | 50,000,000 | 1,000,000,000 |
| `memory_limit` | 64 MiB | 256 MiB |
| `output_limit` | 16 MiB | 64 MiB |

The result is returned as `BinaryResponse`: `data` is stdout, `message` is
stderr, and `status` is the WASI exit code. Filesystem access is not exposed.

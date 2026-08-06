use super::wasi;
use std::collections::HashMap;
use wasmi::core::Trap;
use wasmi::{Config, Engine, Instance, Linker, Module as WasmiModule, Store, StoreLimitsBuilder};

const DEFAULT_ENTRY_POINT: &str = "_start";
const DEFAULT_FUEL: u64 = 50_000_000;
const MAX_FUEL: u64 = 1_000_000_000;
const DEFAULT_MEMORY_LIMIT: usize = 64 * 1024 * 1024;
const MAX_MEMORY_LIMIT: usize = 256 * 1024 * 1024;
const DEFAULT_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
const MAX_OUTPUT_LIMIT: usize = 64 * 1024 * 1024;

pub(super) struct RuntimeOptions {
    program_name: String,
    entry_point: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    stdin: Vec<u8>,
    fuel: u64,
    memory_limit: usize,
    output_limit: usize,
}

impl RuntimeOptions {
    pub(super) fn new(
        program_name: String,
        entry_point: String,
        args: Vec<String>,
        params: HashMap<String, String>,
        stdin: Vec<u8>,
    ) -> Result<Self, String> {
        let fuel = parse_limit(&params, "fuel", DEFAULT_FUEL, MAX_FUEL)?;
        let memory_limit = parse_limit(
            &params,
            "memory_limit",
            DEFAULT_MEMORY_LIMIT as u64,
            MAX_MEMORY_LIMIT as u64,
        )? as usize;
        let output_limit = parse_limit(
            &params,
            "output_limit",
            DEFAULT_OUTPUT_LIMIT as u64,
            MAX_OUTPUT_LIMIT as u64,
        )? as usize;

        let mut env: Vec<_> = params
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "fuel" | "memory_limit" | "output_limit"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        env.sort_unstable_by(|left, right| left.0.cmp(&right.0));

        Ok(Self {
            program_name: if program_name.is_empty() {
                "wasmloader".to_string()
            } else {
                program_name
            },
            entry_point: if entry_point.is_empty() {
                DEFAULT_ENTRY_POINT.to_string()
            } else {
                entry_point
            },
            args,
            env,
            stdin,
            fuel,
            memory_limit,
            output_limit,
        })
    }
}

#[derive(Debug)]
pub(super) struct WasmExecution {
    pub(super) exit_code: i32,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

pub(super) fn execute(wasm: &[u8], options: RuntimeOptions) -> Result<WasmExecution, String> {
    if wasm.is_empty() {
        return Err("WASM bytecode is empty".to_string());
    }
    let mut config = Config::default();
    config.consume_fuel(true);
    let engine = Engine::new(&config);
    let module = WasmiModule::new(&engine, wasm)
        .map_err(|error| format!("failed to parse WASM module: {error}"))?;

    let limits = StoreLimitsBuilder::new()
        .memory_size(options.memory_limit)
        .instances(1)
        .memories(1)
        .build();
    let state = wasi::WasiState::new(
        options.program_name,
        options.args,
        options.env,
        options.stdin,
        limits,
        options.output_limit,
    );
    let mut store = Store::new(&engine, state);
    store.limiter(|state| &mut state.limits);
    store
        .add_fuel(options.fuel)
        .map_err(|error| format!("failed to configure WASM fuel: {error}"))?;

    let mut linker = Linker::new(&engine);
    wasi::register(&mut linker)
        .map_err(|error| format!("failed to register WASI imports: {error}"))?;
    super::wasix::register(&mut linker)
        .map_err(|error| format!("failed to register WASIX imports: {error}"))?;
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|error| format!("failed to instantiate WASM module: {error}"))?
        .start(&mut store)
        .map_err(|error| format!("failed to start WASM module: {error}"))?;

    let exit_code = call_entry(&instance, &mut store, &options.entry_point)?;
    let state = store.into_data();
    Ok(WasmExecution {
        exit_code,
        stdout: state.stdout,
        stderr: state.stderr,
    })
}

fn call_entry(
    instance: &Instance,
    store: &mut Store<wasi::WasiState>,
    entry_point: &str,
) -> Result<i32, String> {
    if let Ok(function) = instance.get_typed_func::<(), ()>(&*store, entry_point) {
        return match function.call(store, ()) {
            Ok(()) => Ok(0),
            Err(error) => handle_call_error(error),
        };
    }

    if let Ok(function) = instance.get_typed_func::<(), i32>(&*store, entry_point) {
        return match function.call(store, ()) {
            Ok(status) => Ok(status),
            Err(error) => handle_call_error(error),
        };
    }

    Err(format!(
        "WASM entry point '{entry_point}' was not found or has an unsupported signature"
    ))
}

fn handle_call_error(error: Trap) -> Result<i32, String> {
    if let Some(status) = error.i32_exit_status() {
        return Ok(status);
    }
    Err(format!("WASM execution failed: {error}"))
}

fn parse_limit(
    params: &HashMap<String, String>,
    key: &str,
    default: u64,
    maximum: u64,
) -> Result<u64, String> {
    let Some(value) = params.get(key) else {
        return Ok(default);
    };
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("invalid {key} value '{value}'"))?;
    if parsed == 0 || parsed > maximum {
        return Err(format!("{key} must be between 1 and {maximum}"));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_START_MODULE: &[u8] = &[
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03,
        0x02, 0x01, 0x00, 0x07, 0x0A, 0x01, 0x06, 0x5F, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00,
        0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B,
    ];

    fn options() -> RuntimeOptions {
        RuntimeOptions {
            program_name: "test".to_string(),
            entry_point: DEFAULT_ENTRY_POINT.to_string(),
            args: Vec::new(),
            env: Vec::new(),
            stdin: Vec::new(),
            fuel: DEFAULT_FUEL,
            memory_limit: DEFAULT_MEMORY_LIMIT,
            output_limit: DEFAULT_OUTPUT_LIMIT,
        }
    }

    #[test]
    fn executes_no_arg_start_function() {
        let result = execute(EMPTY_START_MODULE, options()).unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }

    #[test]
    fn rejects_invalid_bytecode() {
        let error = execute(b"not-wasm", options()).unwrap_err();
        assert!(error.contains("failed to parse WASM module"));
    }

    #[test]
    fn validates_runtime_limits() {
        let mut params = HashMap::new();
        params.insert("fuel".to_string(), "0".to_string());
        assert!(parse_limit(&params, "fuel", DEFAULT_FUEL, MAX_FUEL).is_err());
    }
}

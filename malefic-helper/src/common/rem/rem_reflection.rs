use crate::common::hot_modules::{get_function_address, load_module};
use std::sync::OnceLock;
use crate::common::rem::{RemApi, RemFunctions};

static INIT_STATE: OnceLock<Result<(), String>> = OnceLock::new();
static REM_DLL: OnceLock<Vec<u8>> = OnceLock::new();

static mut REM_FUNCTIONS: RemFunctions = RemFunctions {
    rem_dial: None,
    memory_dial: None,
    memory_read: None,
    memory_write: None,
    memory_close: None,
    cleanup_agent: None,
};

pub struct RemReflection;

impl RemReflection {
    /// 加载REM DLL并初始化
    ///
    /// # Arguments
    /// * `dll_bytes` - REM DLL的字节数据
    ///
    /// # Returns
    /// * `Result<(), String>` - 成功返回Ok(()), 失败返回错误信息
    pub fn load_rem(dll_bytes: Vec<u8>) -> Result<(), String> {
        if INIT_STATE.get().is_some() {
            return Err("REM DLL already init".to_string());
        }

        // 设置DLL数据并初始化函数
        if REM_DLL.set(dll_bytes).is_err() {
            return Err("Failed to set REM DLL data".to_string());
        }

        unsafe { Self::ensure_initialized() }
    }

    unsafe fn ensure_initialized() -> Result<(), String> {
        INIT_STATE
            .get_or_init(|| Self::initialize_functions())
            .clone()
    }

    unsafe fn initialize_functions() -> Result<(), String> {
        let dll_bytes = REM_DLL
            .get()
            .ok_or("REM not initialize, please load rem.dll")?;

        let module = load_module(dll_bytes.clone(), String::from("rem"))
            .map_err(|e| format!("Failed to load module: {:?}", e))?;

        if module.is_null() {
            return Err("Failed to load module: module is null".to_string());
        }

        let module_base = module as *const _;

        // 获取各个函数的地址
        let rem_dial_addr = get_function_address(module_base, "RemDial");
        if rem_dial_addr.is_null() {
            return Err("Failed to get RemDial function".to_string());
        }
        REM_FUNCTIONS.rem_dial = Some(std::mem::transmute(rem_dial_addr));

        let memory_dial_addr = get_function_address(module_base, "MemoryDial");
        if memory_dial_addr.is_null() {
            return Err("Failed to get MemoryDial function".to_string());
        }
        REM_FUNCTIONS.memory_dial = Some(std::mem::transmute(memory_dial_addr));

        let memory_read_addr = get_function_address(module_base, "MemoryRead");
        if memory_read_addr.is_null() {
            return Err("Failed to get MemoryRead function".to_string());
        }
        REM_FUNCTIONS.memory_read = Some(std::mem::transmute(memory_read_addr));

        let memory_write_addr = get_function_address(module_base, "MemoryWrite");
        if memory_write_addr.is_null() {
            return Err("Failed to get MemoryWrite function".to_string());
        }
        REM_FUNCTIONS.memory_write = Some(std::mem::transmute(memory_write_addr));

        let memory_close_addr = get_function_address(module_base, "MemoryClose");
        if memory_close_addr.is_null() {
            return Err("Failed to get MemoryClose function".to_string());
        }
        REM_FUNCTIONS.memory_close = Some(std::mem::transmute(memory_close_addr));

        let cleanup_agent_addr = get_function_address(module_base, "CleanupAgent");
        if cleanup_agent_addr.is_null() {
            return Err("Failed to get CleanupAgent function".to_string());
        }
        REM_FUNCTIONS.cleanup_agent = Some(std::mem::transmute(cleanup_agent_addr));

        Ok(())
    }
}

impl RemApi for RemReflection {
    unsafe fn get_functions(&self) -> Result<&RemFunctions, String> {
        Self::ensure_initialized()?;
        Ok(&REM_FUNCTIONS)
    }
}

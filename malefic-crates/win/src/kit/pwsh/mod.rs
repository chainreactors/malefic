use crate::kit::binding::MaleficPwshExecCommand;

pub unsafe fn pwsh_exec_command(script: &String) -> String {
    MaleficPwshExecCommand(script.as_ptr(), script.len()).into_string()
}

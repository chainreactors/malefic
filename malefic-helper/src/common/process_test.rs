use super::process::Process;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_processes() {
        let processes = match cfg!(target_os = "windows") {
            true => crate::win::process::get_processes(),
            false if cfg!(target_os = "linux") => crate::linux::process::get_processes(),
            false if cfg!(target_os = "macos") => crate::darwin::process::get_processes(),
            _ => panic!("Unsupported platform"),
        };

        assert!(processes.is_ok());
        let processes = processes.unwrap();

        // 验证进程列表不为空
        assert!(!processes.is_empty());

        // 验证至少包含当前进程
        let current_pid = std::process::id();
        assert!(processes.contains_key(&current_pid));

        // 验证进程信息的完整性
        let current_process = &processes[&current_pid];
        assert!(!current_process.name.is_empty());
        assert_eq!(current_process.pid, current_pid);
        assert!(current_process.ppid > 0);

        // 验证其他字段的存在性（不验证具体值）
        assert!(!current_process.uid.is_empty());
        assert!(!current_process.arch.is_empty());
        assert!(!current_process.owner.is_empty());
        assert!(!current_process.path.is_empty());

        // 打印当前进程的信息（用于调试）
        println!("Current process info:");
        println!("  Name: {}", current_process.name);
        println!("  PID: {}", current_process.pid);
        println!("  PPID: {}", current_process.ppid);
        println!("  UID: {}", current_process.uid);
        println!("  Architecture: {}", current_process.arch);
        println!("  Owner: {}", current_process.owner);
        println!("  Path: {}", current_process.path);
        println!("  Args: {}", current_process.args);
    }

    #[test]
    fn test_process_fields() {
        let process = Process {
            name: "test".to_string(),
            pid: 1,
            ppid: 0,
            uid: "0".to_string(),
            arch: "x64".to_string(),
            owner: "root".to_string(),
            path: "/bin/test".to_string(),
            args: "-a -b".to_string(),
        };

        assert_eq!(process.name, "test");
        assert_eq!(process.pid, 1);
        assert_eq!(process.ppid, 0);
        assert_eq!(process.uid, "0");
        assert_eq!(process.arch, "x64");
        assert_eq!(process.owner, "root");
        assert_eq!(process.path, "/bin/test");
        assert_eq!(process.args, "-a -b");
    }
}

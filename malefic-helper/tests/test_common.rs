use malefic_helper::common::net::{get_netstat, get_network_interfaces};

#[test]
pub fn test_interface() {
    println!("{:?}", get_network_interfaces());
}

#[test]
pub fn test_netstat() {
    println!("{:?}", get_netstat());
}

#[cfg(target_os = "windows")]
mod win_tests {
    #[test]
    pub fn test_reg_read() {
        let reg = malefic_helper::win::reg::Registry::new();
        println!("{:?}", reg.read_value("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProgramFilesDir"))
    }
    
    #[test]
    pub fn test_reg_write() {
        let reg = malefic_helper::win::reg::Registry::new();
        println!("{:?}", reg.write("HKEY_USERS", "S-1-5-21-2995121756-649691204-1924976591-1001\\Networks", "ProgramFilesDir", "C:\\Program Files"))
    }
    
    #[test]
    pub fn test_reg_delete() {
        let reg = malefic_helper::win::reg::Registry::new();
        println!("{:?}", reg.delete_value("HKEY_USERS", "S-1-5-21-2995121756-649691204-1924976591-1001\\Networks", "ProgramFilesDir"))
    }
    
    #[test]
    pub fn test_shellcode_loader() {
        // 读取loader.bin文件
        let file = std::fs::read("../loader.bin").unwrap();
        unsafe {
            let loader = malefic_helper::loader::mei::apc::loader(file, 
                false, "C:\\Windows\\System32\\notepad.exe\x00".as_ptr() as _, 0, true);
            println!("{:#?}", loader);
        }
    }
}
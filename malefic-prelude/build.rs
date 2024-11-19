use std::fs;
use std::path::Path;
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../resources/malefic.rc");
    println!("test build!");
    #[cfg(target_os = "windows")]
    {
        let mut rc = winres::WindowsResource::new();
        let current_dir = std::env::current_dir().expect("Failed to get current directory");
        let rc_path = Path::new("../resources/malefic.rc");
        let absolute_rc_path = fs::canonicalize(current_dir.join(rc_path))
            .expect("Failed to canonicalize the resource file path");
        println!("rc_path: {}", absolute_rc_path.to_str().unwrap());
        let mut absolute_rc_str = absolute_rc_path.to_str().expect("Path is not valid UTF-8");
        if absolute_rc_str.starts_with(r"\\?\") {
            absolute_rc_str = &absolute_rc_str[4..];
        }
        println!("absolute_rc_str: {}", absolute_rc_str);
        rc.set_resource_file(absolute_rc_str);
        rc.compile().expect("Failed to compile resource file");
    }
}

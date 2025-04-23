
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../resources/malefic.rc");
    println!("test build!");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());
   
    if target_os == "windows" {
        let current_dir = std::env::current_dir().expect("Failed to get current directory");
        let rc_path = std::path::Path::new("../resources/malefic.rc");
        let absolute_rc_path = std::fs::canonicalize(current_dir.join(rc_path))
            .expect("Failed to canonicalize the resource file path");
        println!("rc_path: {}", absolute_rc_path.to_str().unwrap());

        let _ = embed_resource::compile(absolute_rc_path, embed_resource::NONE);
    }
}

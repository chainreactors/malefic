

fn main() {
    #[cfg(feature = "prebuild")]
    {
        use std::path::PathBuf;
        use std::{env, fs};
        loop {
            if env::var("CARGO_CFG_TARGET_OS").unwrap() != "windows" {
                break;
            }
            let mut default_prefix = "libmalefic-win-kit-community-gnu";
            let mut default_suffix = ".a";
            let mut default_arch = "x64";
            let mut default_destination = "libmalefic_win_kit.a";
            if env::var("CARGO_CFG_TARGET_ENV").unwrap() == "msvc" {
                default_prefix = "malefic-win-kit-community-msvc";
                default_suffix = ".lib";
                default_destination = "malefic_win_kit.lib";
            }
            if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "x86" {
                default_arch = "x32";
            }
            let lib_name = format!("{}-{}{}", 
                default_prefix, default_arch, default_suffix);
            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
            let current_dir = env::current_dir().unwrap();
            let root_dir = current_dir.parent().unwrap();
            let source_path = root_dir.join("resources").join(lib_name);
            let destination_path = out_dir.join(default_destination);
            fs::copy(&source_path, &destination_path).expect(
                &format!("Failed to copy file {}", 
                source_path.display()).to_string());
            println!("cargo:rustc-link-search=native={}", out_dir.display());
            println!("cargo:rustc-link-lib=static={}", "malefic_win_kit");
            break;
        }
    }
}

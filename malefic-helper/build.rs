fn main() {
    #[cfg(feature = "prebuild")]
    {
        use std::{env, fs, path::PathBuf};

        if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
            let (prefix, suffix, destination) = match env::var("CARGO_CFG_TARGET_ENV").unwrap().as_str() {
                "msvc" => ("malefic-win-kit-community-msvc", ".lib", "malefic_win_kit.lib"),
                _ => ("libmalefic-win-kit-community-gnu", ".a", "libmalefic_win_kit.a"),
            };

            let arch = if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "x86" {
                "x32"
            } else {
                "x64"
            };

            let lib_name = format!("{prefix}-{arch}{suffix}");
            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
            let source_path = env::current_dir()
                .unwrap()
                .parent()
                .unwrap()
                .join("resources")
                .join(&lib_name);

            // 检查 source_path 是否存在
            if !source_path.exists() {
                panic!("Source file not found: {}", source_path.display());
            }

            let destination_path = out_dir.join(destination);

            fs::copy(&source_path, &destination_path).expect(&format!(
                "Failed to copy file {}",
                source_path.display()
            ));

            println!("cargo:rustc-link-search=native={}", out_dir.display());
            println!("cargo:rustc-link-lib=static=malefic_win_kit");
        }
    }
}

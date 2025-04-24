fn main() {
    use std::env;
    println!("cargo:rerun-if-changed=build.rs");
    let mut is_msvc = false;
    let mut default_arch = "x64";
    if env::var("CARGO_CFG_TARGET_OS").unwrap().ne(&"windows") {
        return;
    }
    if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "x86" {
        default_arch = "x32";
    }
    if env::var("CARGO_CFG_TARGET_ENV").unwrap().eq(&"msvc") {
        is_msvc = true;
        println!("cargo:rustc-link-arg-bins=/ENTRY:_start");
        println!("cargo:rustc-link-arg-bins=/SUBSYSTEM:WINDOWS");
    } else {
        // let default_linker = "Linker";
        // let arch = &default_arch[1..];
        // let linker = format!("{}{}.{}", default_linker, arch, "ld");
        // let current_dir = env::current_dir()
        //     .expect("Failed to get current directory");
        // let absolute_linker_path = current_dir.join(linker);
        println!("cargo:rustc-link-arg=-nostdlib");
        println!("cargo:rustc-link-arg=-nostartfiles");
        println!("cargo:rustc-link-arg=-fno-ident");
        println!("cargo:rustc-link-arg=-fpack-struct=8");
        println!("cargo:rustc-link-arg=-Wl,--gc-sections");
        println!("cargo:rustc-link-arg=-Wl,--strip-all");
        println!("cargo:rustc-link-arg=-falign-jumps=1");
        println!("cargo:rustc-link-arg=-static");
        println!("cargo:rustc-link-arg=-w");
        println!("cargo:rustc-link-arg=-falign-labels=1");
        println!("cargo:rustc-link-arg=-Wl,-s,--no-seh,--enable-stdcall-fixup");
        println!("cargo:rustc-link-arg=-Wl,--subsystem,windows");
        println!("cargo:rustc-link-arg=-Wl,-e_start");
    }

    #[cfg(feature = "prebuild")]
    {
        use std::path::PathBuf;
        use std::fs;
        if env::var("CARGO_CFG_TARGET_OS").unwrap() != "windows" {
            return;
        }
        let mut default_prefix = "libmalefic-win-kit-community-pulse-gnu";
        let mut default_suffix = ".a";
        let mut default_destination = "libmalefic_win_kit_pulse.a";
        let mut ollvm = "";
        if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "x86" {
            default_arch = "x32";
        }
        if is_msvc {
            default_prefix = "malefic-win-kit-community-pulse-msvc";
            default_suffix = ".lib";
            default_destination = "malefic_win_kit_pulse.lib";
        } else {
            let ollvm_flag_path = env::current_dir()
                            .unwrap()
                            .parent()
                            .unwrap()
                            .join("resources/ollvm-flags");
            if ollvm_flag_path.exists() {
                ollvm = "ollvm";
            }
        }
        

        let lib_name = format!("{}-{}-{}{}", 
            default_prefix, default_arch, ollvm, default_suffix);
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let current_dir = env::current_dir().unwrap();
        let root_dir = current_dir.parent().unwrap();
        let source_path = root_dir.join("resources").join(lib_name);
        let destination_path = out_dir.join(default_destination);
        fs::copy(&source_path, &destination_path).expect(
            &format!("Failed to copy file {}", 
            source_path.display()).to_string());
        println!("cargo:rustc-link-search=native={}", out_dir.display());
        println!("cargo:rustc-link-lib=static={}", "malefic_win_kit_pulse");
        return;
    }
}
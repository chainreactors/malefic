use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();

    if !target.contains("windows") {
        panic!("malefic-pulse only supports Windows targets");
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=scripts/linker.ld");

    let is_msvc = target.contains("msvc");

    // Both exe and shellcode modes use -nostdlib (pulse is always no_std).
    // The only difference: shellcode mode adds a linker script to merge all
    // sections into a single .text for objcopy extraction.
    if is_msvc {
        println!("cargo:rustc-link-arg-bins=/ENTRY:stardust");
        println!("cargo:rustc-link-arg-bins=/SUBSYSTEM:WINDOWS");
    } else {
        let entry = if target.contains("x86_64") {
            "stardust"
        } else {
            "_stardust"
        };

        println!("cargo:rustc-link-arg-bins=-nostdlib");
        println!("cargo:rustc-link-arg-bins=-nostartfiles");
        println!("cargo:rustc-link-arg-bins=-static");
        println!("cargo:rustc-link-arg-bins=-fno-ident");
        println!("cargo:rustc-link-arg-bins=-Wl,-e{}", entry);
        println!("cargo:rustc-link-arg-bins=-Wl,--gc-sections");
        println!("cargo:rustc-link-arg-bins=-Wl,--strip-all");
        println!("cargo:rustc-link-arg-bins=-Wl,-s,--no-seh,--enable-stdcall-fixup");
        println!("cargo:rustc-link-arg-bins=-Wl,--subsystem,windows");

        // Shellcode mode: custom linker script merges everything into .text
        #[cfg(feature = "shellcode")]
        {
            let linker_script = format!(
                "{}/scripts/linker.ld",
                env::var("CARGO_MANIFEST_DIR").unwrap()
            );
            println!("cargo:rustc-link-arg-bins=-T{}", linker_script);
        }
    }
}

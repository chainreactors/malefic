use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().expect("workspace root");
    let resources_dir = workspace_root.join("resources");

    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rerun-if-changed={}",
        resources_dir.join("malefic.rc").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        resources_dir.join("YY-Thunks-Objs").display()
    );
    println!("cargo:rerun-if-env-changed=YY_THUNKS_TARGET_OS");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());
    if target_os != "windows" {
        return;
    }

    link_yy_thunks(&resources_dir);

    // embed_resource produces MSVC .lib; GNU linker can't read it
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env != "gnu" {
        compile_resources(&resources_dir);
    }
}

fn link_yy_thunks(resources_dir: &PathBuf) {
    let compat_target = match env::var("YY_THUNKS_TARGET_OS") {
        Ok(v) if !v.is_empty() => v,
        _ => return,
    };

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let arch_folder = match target_arch.as_str() {
        "x86_64" => "x64",
        "x86" => "x86",
        _ => return,
    };
    let obj_filename = format!("YY_Thunks_for_{}.obj", compat_target);
    let obj_path = resources_dir
        .join("YY-Thunks-Objs")
        .join("objs")
        .join(arch_folder)
        .join(&obj_filename);

    if obj_path.exists() {
        println!("cargo:rustc-link-arg={}", obj_path.display());
        println!(
            "cargo:warning=Linking YY-Thunks for {} on {}",
            compat_target, target_arch
        );
    }
}

fn compile_resources(resources_dir: &PathBuf) {
    let rc_path = resources_dir.join("malefic.rc");
    if !rc_path.exists() {
        println!("cargo:warning=malefic.rc not found, skipping resource compilation");
        return;
    }

    use embed_resource::CompilationResult;
    match embed_resource::compile(&rc_path, embed_resource::NONE) {
        CompilationResult::Ok => println!("cargo:warning=embed_resource compiled successfully"),
        CompilationResult::Failed(e) => println!("cargo:warning=embed_resource failed: {}", e),
        CompilationResult::NotAttempted(reason) => {
            println!("cargo:warning=RC compiler not found: {}", reason)
        }
        CompilationResult::NotWindows => {}
    }
}

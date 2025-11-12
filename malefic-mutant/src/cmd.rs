use std::str::FromStr;

use crate::config::{GenerateArch, Version};
use crate::Platform;
use clap::{Parser, Subcommand};
use strum_macros::Display;

#[derive(Parser)]
#[command(name = "malefic-config", about = "Config malefic beacon and prelude.")]
pub struct Cli {
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

        #[command(subcommand)]
        command: BuildCommands,
    },

    #[command(subcommand)]
    Tool(Tool),
}

// 配置类命令
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

    /// Generate ProxyDLL for DLL hijacking
    ProxyDLL {
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
    Pulse,

    /// Build proxy-dll
    #[command(name = "proxy-dll")]
    ProxyDll,
}

#[derive(Subcommand)]
pub enum SigForgeCommands {
    /// Extract signature from a signed PE file
    Extract {
        /// Input PE file
        #[arg(short = 'i', long)]
        input: String,
        /// Output signature file
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    /// Copy signature from one PE file to another
    Copy {
        /// Source PE file (signed)
        #[arg(short = 's', long)]
        source: String,
        /// Target PE file (to be signed)
        #[arg(short = 't', long)]
        target: String,
        /// Output file path
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    /// Inject signature from file into PE file
    Inject {
        /// Signature file
        #[arg(short = 's', long)]
        signature: String,
        /// Target PE file
        #[arg(short = 't', long)]
        target: String,
        /// Output file path
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    /// Remove signature from PE file
    Remove {
        /// Input PE file
        #[arg(short = 'i', long)]
        input: String,
        /// Output file path
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    Check {
        #[arg(short = 'i', long)]
        input: String,
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

    /// PE file signature manipulation tool
    #[command(name = "sigforge")]
    SigForge {
        #[command(subcommand)]
        command: SigForgeCommands,
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
}

use std::str::FromStr;

use clap::{Parser, Subcommand};
use crate::{GenerateArch, Platform, Version};

#[derive(Parser)]
#[command(name = "malefic-config", about = "Config malefic beacon and prelude.")]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Config related commands
    Generate {
        /// Choice professional or community
        #[arg(long, short = 'v', global = true, default_value = "community")]
        version: Version,

        /// enable build from source code
        #[arg(long, short = 's', global = true)]
        source: bool,

        #[command(subcommand)]
        command: GenerateCommands,
    },

    /// Generate related commands
    #[command(subcommand)]
    Build(BuildCommands),
}

// `ConfigOptions` 包含 `ConfigCommands` 子命令和全局配置选项

// 配置类命令
#[derive(Subcommand)]
pub enum GenerateCommands {
    /// Config beacon
    Beacon ,

    /// Config bind
    Bind ,

    /// Config prelude
    Prelude {
        yaml_path: String,

        /// Custom resources dir, default "./resources/"
        #[arg(long, default_value = "resources")]
        resources: String,

        #[arg(long, default_value = "maliceofinternal")]
        key: String,
    },

    /// Config modules
    Modules {
        /// Choice modules
        modules: String,
    },

    /// Generate pulse
    Pulse {
        /// Choice arch x86/x64
        arch: GenerateArch,

        /// platform, win
        platform: Platform,
    },

}

#[derive(Clone)]
pub enum SrdiType {
    LINK,
    MALEFIC
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

#[derive(Subcommand)]
pub enum BuildCommands {
    /// Generate TinyTools
    #[command(subcommand)]
    TinyTools(TinyTools),

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
}

#[derive(Subcommand)]
pub enum TinyTools {
    /// generate calc shellcode
    Calc {
        /// choice platform,
        platform: String,
        /// choice arch x86/x64
        arch: String,
    },
    /// generate reverse shell shellcode
    ReverseShell {
        /// choice platform,
        platform: String,
        /// choice arch x86/x64
        arch: String,
        /// choice type
        #[arg(long, default_value = "tcp")]
        r#type: String,
        /// choice ip
        ip: String,
        /// choice port
        port: String,
    }
}
use std::str::FromStr;

use crate::{GenerateArch, Platform, Version};
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
        #[arg(long, short = 'c', global = true, default_value = "config.yaml")]
        config: String,

        #[command(subcommand)]
        command: GenerateCommands,
    },

    /// auto build
    Build {
        /// Config file path
        #[arg(long, short = 'c', global = true, default_value = "config.yaml")]
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
}

use chrono::Local;
use colored::*;
use log::{Level, LevelFilter, Metadata, Record};

pub fn init() {
    log::set_logger(&MutantLogger).unwrap();
    log::set_max_level(LevelFilter::Info);
}

struct MutantLogger;

impl log::Log for MutantLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level_str = match record.level() {
                Level::Error => record.level().to_string().red(),
                Level::Warn => record.level().to_string().yellow(),
                Level::Info => record.level().to_string().green(),
                Level::Debug => record.level().to_string().blue(),
                Level::Trace => record.level().to_string().normal(),
            };

            let timestamp = Local::now().format("%H:%M:%S");

            println!(
                "{} {} {}",
                timestamp.to_string().blue(),
                level_str,
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

#[macro_export]
macro_rules! log_success {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        log::info!("{} {}", "✓".green() , format!($($arg)*))
    }}
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        log::error!("{} {}", "✗".red(), format!($($arg)*))
    }}
}

#[macro_export]
macro_rules! log_warning {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        log::warn!("{} {}", "!".yellow(), format!($($arg)*))
    }}
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        log::info!("{} {}", "→".blue(), format!($($arg)*))
    }}
}

#[macro_export]
macro_rules! log_step {
    ($($arg:tt)*) => {{
        use colored::Colorize;
        log::info!("{} {}", "⚡".cyan(), format!($($arg)*))
    }}
}

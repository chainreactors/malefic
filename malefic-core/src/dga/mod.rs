mod algorithm;
mod generator;

pub use algorithm::DgaAlgorithm;
pub use generator::DgaGenerator;

use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc, Timelike, Datelike};
use chrono::TimeZone;

/// DGA时间窗口结构
#[derive(Debug, Clone, PartialEq)]
pub struct TimeWindow {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour_segment: u32,
}

impl TimeWindow {
    /// 根据当前时间和间隔小时数创建时间窗口
    pub fn from_timestamp(timestamp: u64, interval_hours: u32) -> Self {
        // 使用 chrono 0.4 的API
        let dt = DateTime::from_timestamp(timestamp as i64, 0)
            .unwrap_or_else(|| Utc::now());
        
        let hour_segment = dt.hour() / interval_hours;
        
        Self {
            year: dt.year(),
            month: dt.month(),
            day: dt.day(),
            hour_segment,
        }
    }
    
    /// 获取当前时间窗口
    pub fn current(interval_hours: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self::from_timestamp(now, interval_hours)
    }
    
    /// 获取前一个时间窗口
    pub fn previous(&self, interval_hours: u32) -> Self {
        let current_timestamp = self.to_timestamp();
        let previous_timestamp = current_timestamp.saturating_sub((interval_hours * 3600) as u64);
        Self::from_timestamp(previous_timestamp, interval_hours)
    }
    
    /// 转换为时间戳（用于计算）
    fn to_timestamp(&self) -> u64 {
        // 使用 chrono 0.4 的API创建时间
        if let Some(dt) = Utc.with_ymd_and_hms(
            self.year, 
            self.month, 
            self.day, 
            self.hour_segment * 2, // 假设interval_hours=2
            0, 
            0
        ).single() {
            dt.timestamp() as u64
        } else {
            // 如果时间无效，返回当前时间戳
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }
    }
    
    /// 生成时间窗口的种子字符串
    pub fn to_seed_string(&self) -> String {
        format!("{:04}{:02}{:02}{:02}", self.year, self.month, self.day, self.hour_segment)
    }
}

/// DGA域名
#[derive(Debug, Clone)]
pub struct DgaDomain {
    pub domain: String,
    pub seed: String,
    pub prefix: String,
    pub suffix: String,
}

/// DGA错误类型
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

use cron::Schedule;
use chrono::{DateTime, Utc};
use std::str::FromStr;
use nanorand::{WyRand, Rng};

pub struct CronScheduler {
    schedule: Schedule,
    jitter: f64,
}

impl CronScheduler {
    /// 创建新的cron调度器
    pub fn new(expression: &str, jitter: f64) -> Result<Self, cron::error::Error> {
        let schedule = Schedule::from_str(expression)?;
        Ok(Self { schedule, jitter })
    }

    pub fn next_interval(&self) -> u64 {
        let now = Utc::now();

        // 获取下次执行时间
        let next_time = self.schedule.upcoming(Utc).next()
            .unwrap_or_else(|| now + chrono::Duration::seconds(30)); // 默认30秒后

        // 计算时间差
        let duration = next_time.signed_duration_since(now);
        let base_ms = duration.num_milliseconds().max(0) as u64;

        // 应用jitter
        self.apply_jitter(base_ms)
    }
    
    pub fn next_interval_with_out_jitter(&self) -> u64 {
        let now = Utc::now();
        
        let next_time = self.schedule.upcoming(Utc).next()
            .unwrap_or_else(|| now + chrono::Duration::seconds(30));
        
        let duration = next_time.signed_duration_since(now);
        let base_ms = duration.num_milliseconds().max(0) as u64;
        
        base_ms
    }
    
    /// 计算从指定时间到下次执行的间隔
    pub fn next_interval_from(&self, from: DateTime<Utc>) -> u64 {
        let next_time = self.schedule.after(&from).next()
            .unwrap_or_else(|| from + chrono::Duration::seconds(30));
        
        let duration = next_time.signed_duration_since(from);
        let base_ms = duration.num_milliseconds().max(0) as u64;
        
        self.apply_jitter(base_ms)
    }
    
    /// 应用jitter抖动
    fn apply_jitter(&self, base_ms: u64) -> u64 {
        if self.jitter == 0.0 {
            return base_ms;
        }
        
        let mut rng = WyRand::new();
        let jitter_range = (base_ms as f64 * self.jitter) as u64;
        
        if jitter_range == 0 {
            return base_ms;
        }
        
        // 生成 -jitter_range 到 +jitter_range 的随机偏移
        let offset = rng.generate_range(0..=(jitter_range * 2));
        let signed_offset = offset as i64 - jitter_range as i64;
        
        (base_ms as i64 + signed_offset).max(1000) as u64  // 最小1秒
    }
    
    /// 检查当前时间是否在调度范围内
    pub fn is_active_now(&self) -> bool {
        let now = Utc::now();
        self.schedule.includes(now)
    }
    
    /// 获取下次执行时间
    pub fn next_execution_time(&self) -> Option<DateTime<Utc>> {
        self.schedule.upcoming(Utc).next()
    }
    
    /// 获取调度表达式
    pub fn expression(&self) -> String {
        self.schedule.source().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cron_scheduler() {
        // 每30秒执行
        let scheduler = CronScheduler::new("0/30 * * * * *", 0.1).unwrap();
        let interval = scheduler.next_interval();
        assert!(interval > 0);
        assert!(interval <= 30000 + 3000); // 30秒 + 10%抖动
        
        // 工作时间每分钟执行
        let scheduler = CronScheduler::new("0 * 9-17 * * *", 0.0).unwrap();
        assert!(scheduler.next_interval() > 0);
    }
    
    #[test]
    fn test_jitter() {
        let scheduler = CronScheduler::new("0/10 * * * * *", 0.2).unwrap();
        
        // 多次计算，应该有不同的结果（由于jitter）
        let intervals: Vec<u64> = (0..5).map(|_| scheduler.next_interval()).collect();
        
        // 检查是否有变化（jitter生效）
        let all_same = intervals.windows(2).all(|w| w[0] == w[1]);
        assert!(!all_same, "Jitter should cause variation in intervals");
    }
}

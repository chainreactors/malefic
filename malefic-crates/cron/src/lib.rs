use chrono::Utc;
use cron::Schedule;
use std::str::FromStr;

pub struct Cronner {
    schedule: Schedule,
    jitter: f64,
}

impl Cronner {
    pub fn new(expression: &str, jitter: f64) -> Result<Self, cron::error::Error> {
        let schedule = Schedule::from_str(expression)?;
        Ok(Self { schedule, jitter })
    }

    pub fn next_interval(&self) -> u64 {
        const DEFAULT_INTERVAL_SECS: i64 = 30;
        const MIN_INTERVAL_MS: u64 = 1000;

        let now = Utc::now();
        let next_time = self
            .schedule
            .upcoming(Utc)
            .next()
            .unwrap_or_else(|| now + chrono::Duration::seconds(DEFAULT_INTERVAL_SECS));

        let base_ms = next_time
            .signed_duration_since(now)
            .num_milliseconds()
            .max(0) as u64;

        self.apply_jitter(base_ms).max(MIN_INTERVAL_MS)
    }

    fn apply_jitter(&self, base_ms: u64) -> u64 {
        if self.jitter == 0.0 {
            return base_ms;
        }

        let jitter_range = (base_ms as f64 * self.jitter) as u64;
        if jitter_range == 0 {
            return base_ms;
        }

        let offset =
            malefic_common::random::range_u64(0, jitter_range * 2 + 1) as i64 - jitter_range as i64;

        (base_ms as i64).saturating_add(offset).max(0) as u64
    }

    pub fn expression(&self) -> String {
        self.schedule.source().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cron_scheduler() {
        let scheduler = Cronner::new("0/30 * * * * *", 0.1).unwrap();
        let interval = scheduler.next_interval();
        assert!(interval > 0);
        assert!(interval <= 30000 + 3000);

        let scheduler = Cronner::new("0 * 9-17 * * *", 0.0).unwrap();
        assert!(scheduler.next_interval() > 0);
    }

    #[test]
    fn test_jitter() {
        let scheduler = Cronner::new("0/10 * * * * *", 0.2).unwrap();
        let intervals: Vec<u64> = (0..5).map(|_| scheduler.next_interval()).collect();
        let all_same = intervals.windows(2).all(|w| w[0] == w[1]);
        assert!(!all_same, "Jitter should cause variation in intervals");
    }
}

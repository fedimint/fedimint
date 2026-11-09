//! Windows over the per-day volume counters that modules keep.

/// The days a volume window covers, `first_day..end_day`, ending with the
/// current day.
pub struct VolumeWindow {
    pub first_day: u64,
    pub end_day: u64,
}

impl VolumeWindow {
    pub fn new(today: u64, days: u64) -> Self {
        Self {
            first_day: (today + 1).saturating_sub(days),
            end_day: today + 1,
        }
    }

    /// Whether counting covered the whole window. `start` is the clock value,
    /// in `units_per_day` units, when counting started; 0 means the clock had
    /// not started, so counting started when the federation formed.
    ///
    /// Software from before the counters may have processed flows at the
    /// very clock value counting started at, so the day counting started on
    /// is never complete, even when it started at the day's first unit.
    pub fn is_complete(&self, start: Option<u64>, units_per_day: u64) -> bool {
        match start {
            None => false,
            Some(0) => true,
            Some(start) => start < self.first_day * units_per_day,
        }
    }
}

#[cfg(test)]
mod tests;

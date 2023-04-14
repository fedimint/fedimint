use std::borrow::Cow;
use std::time;

use fedimint_logging::LOG_TIMING;
use tracing::{debug, info, trace, warn, Level};

/// Data inside `TimeReporter`, in another struct to be able to move it out of
/// without violating `drop` consistency
struct TimeReporterInner {
    name: Cow<'static, str>,
    level: Level,
    start: time::SystemTime,
    threshold: Option<time::Duration>,
}

impl TimeReporterInner {
    fn report(&mut self) {
        let duration = crate::time::now()
            .duration_since(self.start)
            .map_err(|error| {
                warn!(
                    target: LOG_TIMING,
                    %error,
                    "Timer reporter duration overflow. This should not happen."
                );
                error
            })
            .unwrap_or_default();

        // even `event!` doesn't support non-constant values, so we have to do a match
        // here
        let duration_ms = duration.as_millis();
        match self.level {
            Level::TRACE => {
                trace!(
                    target: LOG_TIMING,
                    name = %self.name,
                    duration_ms,
                    "Operation timing"
                );
            }
            Level::DEBUG => {
                debug!(
                    target: LOG_TIMING,
                    name = %self.name,
                    duration_ms,
                    "Operation timing"
                );
            }
            Level::INFO => {
                info!(
                    target: LOG_TIMING,
                    name = %self.name,
                    duration_ms,
                    "Operation timing"
                );
            }
            // anything else is just a warn, whatever; it's long enough
            _ => {
                warn!(
                    target: LOG_TIMING,
                    name = %self.name,
                    duration_ms,
                    "Operation timing"
                );
            }
        }
        if let Some(threshold) = self.threshold {
            if duration < threshold {
                warn!(
                    target: LOG_TIMING,
                    name = %self.name,
                    duration_ms = duration.as_millis(),
                    threshold_ms = threshold.as_millis(),
                    "Operation time exeeded threshold"
                );
            }
        }
    }
}

pub struct TimeReporter {
    /// Inner data
    ///
    /// If `None`, time reported has been moved out from and is now a no-op
    inner: Option<TimeReporterInner>,
}

impl TimeReporter {
    pub fn new(name: &'static str) -> Self {
        Self {
            inner: Some(TimeReporterInner {
                name: Cow::from(name),
                level: Level::DEBUG,
                start: crate::time::now(),
                threshold: None,
            }),
        }
    }

    pub fn level(mut self, level: tracing::Level) -> Self {
        Self {
            inner: self
                .inner
                .take()
                .map(|inner| TimeReporterInner { level, ..inner }),
        }
    }

    /// Add a threshold, which will log a warning if exeeded
    pub fn threshold(mut self, threshold: time::Duration) -> Self {
        Self {
            inner: self.inner.take().map(|inner| TimeReporterInner {
                threshold: Some(threshold),
                ..inner
            }),
        }
    }

    /// Handy alias for [`Self::threshold`]
    pub fn threshold_millis(self, millis: u64) -> Self {
        self.threshold(time::Duration::from_millis(millis))
    }

    pub fn info(self) -> Self {
        self.level(Level::INFO)
    }

    pub fn cancel(&mut self) {
        self.inner.take();
    }

    pub fn finish(self) {
        /* drop */
    }
}

impl Drop for TimeReporter {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            inner.report()
        }
    }
}

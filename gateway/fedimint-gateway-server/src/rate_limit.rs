use std::sync::Mutex;
use std::time::SystemTime;

use fedimint_core::time::now;

/// A global token bucket limiting the rate of unauthenticated requests that
/// create state on the gateway or its Lightning node.
///
/// The bucket holds at most `burst` tokens and refills at `refill_per_second`;
/// each request takes one token and is rejected if none is available. The
/// limiter is transport-agnostic since it guards the request handler itself
/// rather than the HTTP layer, so requests arriving over Iroh are limited as
/// well.
#[derive(Debug)]
pub struct TokenBucketRateLimiter {
    burst: f64,
    refill_per_second: f64,
    state: Mutex<TokenBucketState>,
}

#[derive(Debug)]
struct TokenBucketState {
    tokens: f64,
    last_refill: SystemTime,
}

impl TokenBucketRateLimiter {
    pub fn new(burst: u32, refill_per_second: u32) -> Self {
        Self {
            burst: f64::from(burst),
            refill_per_second: f64::from(refill_per_second),
            state: Mutex::new(TokenBucketState {
                tokens: f64::from(burst),
                last_refill: now(),
            }),
        }
    }

    /// Takes a token from the bucket if one is available, returning whether
    /// the request may proceed.
    pub fn try_acquire(&self) -> bool {
        self.try_acquire_at(now())
    }

    fn try_acquire_at(&self, now: SystemTime) -> bool {
        let mut state = self
            .state
            .lock()
            .expect("No code holding the lock can panic");

        // `SystemTime` is not monotonic; if the clock moved backwards, refill
        // nothing and restart the refill measurement from the earlier time.
        let elapsed = now
            .duration_since(state.last_refill)
            .unwrap_or_default()
            .as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.refill_per_second).min(self.burst);
        state.last_refill = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests;

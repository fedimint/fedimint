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
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn burst_is_granted_then_rejected() {
        let limiter = TokenBucketRateLimiter::new(3, 1);
        let start = now();

        for _ in 0..3 {
            assert!(limiter.try_acquire_at(start));
        }
        assert!(!limiter.try_acquire_at(start));
    }

    #[test]
    fn tokens_refill_over_time() {
        let limiter = TokenBucketRateLimiter::new(2, 5);
        let start = now();

        assert!(limiter.try_acquire_at(start));
        assert!(limiter.try_acquire_at(start));
        assert!(!limiter.try_acquire_at(start));

        // 200ms at 5 tokens/sec refills exactly one token.
        let later = start + Duration::from_millis(200);
        assert!(limiter.try_acquire_at(later));
        assert!(!limiter.try_acquire_at(later));
    }

    #[test]
    fn refill_is_capped_at_burst() {
        let limiter = TokenBucketRateLimiter::new(2, 5);
        let start = now();

        // After a long idle period only `burst` tokens are available.
        let much_later = start + Duration::from_secs(60);
        assert!(limiter.try_acquire_at(much_later));
        assert!(limiter.try_acquire_at(much_later));
        assert!(!limiter.try_acquire_at(much_later));
    }

    #[test]
    fn backwards_clock_jump_refills_nothing() {
        let limiter = TokenBucketRateLimiter::new(2, 5);
        let start = now();

        assert!(limiter.try_acquire_at(start));
        assert!(limiter.try_acquire_at(start));

        // A clock rollback must not grant tokens or panic.
        let earlier = start - Duration::from_secs(60);
        assert!(!limiter.try_acquire_at(earlier));
    }
}

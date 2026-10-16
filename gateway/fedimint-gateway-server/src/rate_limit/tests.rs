use std::time::Duration;

use fedimint_core::time::now;

use super::TokenBucketRateLimiter;

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

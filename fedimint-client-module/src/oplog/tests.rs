use futures::stream;
use serde_json::Value;

use super::UpdateStreamOrOutcome;

#[tokio::test]
async fn test_await_outcome_cached() {
    let test_value = serde_json::json!({"status": "completed", "amount": 100});
    let cached_outcome = UpdateStreamOrOutcome::Outcome(test_value.clone());
    let result = cached_outcome.await_outcome().await;
    assert_eq!(result, Some(test_value));
}

#[tokio::test]
async fn test_await_outcome_uncached_with_updates() {
    let update_stream = Box::pin(stream::iter(vec![
        Value::from(0),
        Value::from(1),
        Value::from(2),
    ]));
    let uncached_outcome = UpdateStreamOrOutcome::UpdateStream(update_stream);
    let result = uncached_outcome.await_outcome().await;
    assert_eq!(result, Some(Value::from(2)));
}

#[tokio::test]
async fn test_await_outcome_uncached_empty_stream() {
    let empty_stream = Box::pin(stream::empty::<serde_json::Value>());
    let uncached_outcome = UpdateStreamOrOutcome::UpdateStream(empty_stream);
    let result = uncached_outcome.await_outcome().await;
    assert_eq!(result, None);
}

#[tokio::test]
async fn test_await_outcome_uncached_single_update() {
    let update_stream = Box::pin(stream::once(async { Value::from(0) }));
    let uncached_outcome = UpdateStreamOrOutcome::UpdateStream(update_stream);
    let result = uncached_outcome.await_outcome().await;
    assert_eq!(result, Some(Value::from(0)));
}

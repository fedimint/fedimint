use std::convert::Infallible;
use std::future::pending;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use fedimint_core::config::FederationId;
use futures::{FutureExt, poll};

use super::{SharedApiScope, SharedCache};

fn cache(ttl: Option<Duration>) -> SharedCache<u64, Vec<u64>> {
    SharedCache::new(NonZeroUsize::new(1).unwrap(), ttl)
}

fn scope() -> SharedApiScope {
    SharedApiScope::new(FederationId::dummy(), 0)
}

#[tokio::test]
async fn shares_in_flight_even_under_eviction_pressure() {
    let cache = cache(None);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let first = cache.get_or_try_init(scope(), 0, || async {
        Ok::<_, Infallible>(rx.await.unwrap())
    });
    let second = cache.get_or_try_init(scope(), 0, || async { panic!("duplicate fetch") });
    tokio::pin!(first, second);
    assert!(poll!(&mut first).is_pending());
    cache
        .get_or_try_init(scope(), 1, || async { Ok::<_, Infallible>(vec![1]) })
        .await
        .unwrap();
    assert!(poll!(&mut second).is_pending());
    tx.send(vec![0]).unwrap();
    let first = first.await.unwrap();
    let second: Result<_, Infallible> = second.await;
    assert!(Arc::ptr_eq(&first, &second.unwrap()));
    // Once idle, an entry can be evicted.
    cache
        .get_or_try_init(scope(), 2, || async { Ok::<_, Infallible>(vec![2]) })
        .await
        .unwrap();
    assert_eq!(cache.entries.lock().await.len(), 1);
}

#[tokio::test]
async fn cancellation_and_errors_are_retryable() {
    let cache = cache(None);
    let mut cancelled =
        Box::pin(cache.get_or_try_init(scope(), 0, pending::<Result<Vec<u64>, ()>>));
    assert_eq!(poll!(&mut cancelled), Poll::Pending);
    drop(cancelled);
    assert!(
        cache
            .get_or_try_init(scope(), 0, || async { Err(()) })
            .await
            .is_err()
    );
    assert_eq!(
        *cache
            .get_or_try_init(scope(), 0, || async { Ok::<_, ()>(vec![3]) })
            .await
            .unwrap(),
        vec![3]
    );
}

#[tokio::test]
async fn snapshots_expire_including_empty_results() {
    let cache = cache(Some(Duration::ZERO));
    cache
        .get_or_try_init(scope(), 0, || async { Ok::<_, ()>(vec![]) })
        .await
        .unwrap();
    assert_eq!(
        *cache
            .get_or_try_init(scope(), 0, || async { Ok::<_, ()>(vec![4]) })
            .await
            .unwrap(),
        vec![4]
    );
    let cache = super::SharedCache::<u64, u64>::new(NonZeroUsize::new(1).unwrap(), None);
    cache
        .get_or_try_init(scope(), 0, || async { Ok::<_, ()>(5) })
        .await
        .unwrap();
    assert_eq!(
        *cache
            .get_or_try_init(scope(), 0, || async { Err(()) })
            .now_or_never()
            .unwrap()
            .unwrap(),
        5
    );
}

#[tokio::test]
async fn scopes_do_not_share() {
    let cache = SharedCache::<u64, u64>::new(NonZeroUsize::new(2).unwrap(), None);
    let other = SharedApiScope::new(FederationId::dummy(), 1);
    cache
        .get_or_try_init(scope(), 0, || async { Ok::<_, ()>(1) })
        .await
        .unwrap();
    assert_eq!(
        *cache
            .get_or_try_init(other, 0, || async { Ok::<_, ()>(2) })
            .await
            .unwrap(),
        2
    );
    let entries = cache.entries.lock().await;
    assert!(entries.contains(&(scope(), 0)) && entries.contains(&(other, 0)));
}

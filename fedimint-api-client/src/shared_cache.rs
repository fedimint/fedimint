//! Caches for validated, account-independent API results.

use std::future::Future;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::time::now;
use lru::LruCache;
use tokio::sync::Mutex;

/// The federation module an API result belongs to.
///
/// Results are only shared within one scope, so a single cache handle can be
/// passed to every account of every federation and module instance in a
/// process. The client framework hands modules their scope as an opaque token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SharedApiScope {
    federation: FederationId,
    instance: ModuleInstanceId,
}

impl SharedApiScope {
    pub fn new(federation: FederationId, instance: ModuleInstanceId) -> Self {
        Self {
            federation,
            instance,
        }
    }
}

type Entry<V> = Arc<Mutex<Option<(SystemTime, Arc<V>)>>>;

/// Shares successful results and concurrent fetches for identical keys within
/// a scope.
///
/// Only the per-key lock is held during a fetch. Cancellation or failure leaves
/// the entry retryable by another caller using its own API. Active entries are
/// never evicted; capacity limits idle entries across all scopes on subsequent
/// accesses.
#[derive(Debug)]
pub struct SharedCache<K: Hash + Eq, V> {
    entries: Mutex<LruCache<(SharedApiScope, K), Entry<V>>>,
    capacity: NonZeroUsize,
    ttl: Option<Duration>,
}

impl<K: Hash + Eq + Clone, V> SharedCache<K, V> {
    pub fn new(capacity: NonZeroUsize, ttl: Option<Duration>) -> Self {
        Self {
            entries: Mutex::new(LruCache::unbounded()),
            capacity,
            ttl,
        }
    }

    pub async fn get_or_try_init<E, F: Future<Output = Result<V, E>>>(
        &self,
        scope: SharedApiScope,
        key: K,
        fetch: impl FnOnce() -> F,
    ) -> Result<Arc<V>, E> {
        let key = (scope, key);
        let entry = {
            let mut entries = self.entries.lock().await;
            // Evict only idle entries, so cache pressure cannot duplicate an
            // in-flight request (including one with waiting callers).
            while entries.len() >= self.capacity.get() {
                let idle = entries
                    .iter()
                    .rev()
                    .find(|(k, v)| *k != &key && Arc::strong_count(v) == 1)
                    .map(|(k, _)| k.clone());
                let Some(idle) = idle else { break };
                entries.pop(&idle);
            }
            entries
                .get_or_insert(key, || Arc::new(Mutex::new(None)))
                .clone()
        };
        let mut value = entry.lock().await;
        if let Some((created, cached)) = &*value
            && self.ttl.is_none_or(|ttl| {
                now()
                    .duration_since(*created)
                    .is_ok_and(|elapsed| elapsed < ttl)
            })
        {
            return Ok(cached.clone());
        }
        let fetched = Arc::new(fetch().await?);
        *value = Some((now(), fetched.clone()));
        Ok(fetched)
    }
}

#[cfg(test)]
mod tests;

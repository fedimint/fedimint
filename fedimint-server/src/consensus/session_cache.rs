//! API-only view of the latest durably completed session.
//!
//! Consensus and reads that must share a database snapshot must not use this
//! cache. The completion watch publishes the index and both encodings together.

use std::future::pending;
use std::sync::Arc;

use fedimint_core::db::{
    Committable, Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::module::SerdeModuleEncoding;
use fedimint_core::session_outcome::SignedSessionOutcome;
use futures::StreamExt;
use tokio::sync::watch;

use super::db::{SignedSessionOutcomeKey, SignedSessionOutcomePrefix};

/// A completed session's canonical JSON wire values, shared without copying.
///
/// Caching `SerdeModuleEncoding` alone would still encode its byte vector and
/// convert it to hex per request. Cache the result of that serialization too.
/// The endpoint framework still allocates an owned JSON response per request.
pub struct CachedSessionOutcome {
    pub index: u64,
    pub signed: Arc<serde_json::Value>,
    pub unsigned: Arc<serde_json::Value>,
}

impl CachedSessionOutcome {
    fn new(index: u64, outcome: &SignedSessionOutcome) -> Self {
        Self {
            index,
            signed: OutcomeFormat::Signed.encode(outcome),
            unsigned: OutcomeFormat::Unsigned.encode(outcome),
        }
    }
}

/// Which of the two existing outcome endpoints is being served.
#[derive(Clone, Copy)]
pub enum OutcomeFormat {
    Signed,
    Unsigned,
}

impl OutcomeFormat {
    fn encode(self, outcome: &SignedSessionOutcome) -> Arc<serde_json::Value> {
        Arc::new(
            match self {
                Self::Signed => serde_json::to_value(SerdeModuleEncoding::from(outcome)),
                Self::Unsigned => {
                    serde_json::to_value(SerdeModuleEncoding::from(&outcome.session_outcome))
                }
            }
            .expect("Session outcome encoding is infallible"),
        )
    }

    fn cached(self, outcome: &CachedSessionOutcome) -> Arc<serde_json::Value> {
        match self {
            Self::Signed => outcome.signed.clone(),
            Self::Unsigned => outcome.unsigned.clone(),
        }
    }
}

pub type CompletedSession = Option<Arc<CachedSessionOutcome>>;

/// Rebuild from the authoritative database before starting the API or
/// consensus.
pub async fn load(db: &Database) -> CompletedSession {
    db.begin_transaction_nc()
        .await
        .find_by_prefix_sorted_descending(&SignedSessionOutcomePrefix)
        .await
        .next()
        .await
        .map(|(key, outcome)| Arc::new(CachedSessionOutcome::new(key.0, &outcome)))
}

/// Publish only after the transaction storing the signed outcome succeeds.
pub fn publish_on_commit(
    dbtx: &mut DatabaseTransaction<'_, Committable>,
    sender: watch::Sender<CompletedSession>,
    index: u64,
    outcome: &SignedSessionOutcome,
) {
    let completed = Arc::new(CachedSessionOutcome::new(index, outcome));
    dbtx.on_commit(move || {
        sender.send_replace(Some(completed));
    });
}

/// Return the exact requested session, never a newer cached session.
pub async fn await_outcome(
    db: &Database,
    receiver: &watch::Receiver<CompletedSession>,
    index: u64,
    format: OutcomeFormat,
) -> Arc<serde_json::Value> {
    let mut receiver = receiver.clone();
    loop {
        // Mark the same snapshot we inspect as seen, before waiting. Do not hold
        // a watch borrow across an await or retain an older outcome while waiting.
        let latest = receiver.borrow_and_update().clone();
        if let Some(latest) = latest {
            if latest.index == index {
                return format.cached(&latest);
            }
            if latest.index > index {
                drop(latest);
                let outcome = db
                    .begin_transaction_nc()
                    .await
                    .get_value(&SignedSessionOutcomeKey(index))
                    .await
                    .expect("There are no gaps in completed session outcomes");
                // Historical recovery is not cached: encode only the requested
                // endpoint, and do not let old reads replace the latest session.
                return format.encode(&outcome);
            }
        }
        // The engine owns the sender for the server lifetime. At shutdown,
        // requests are cancelled; a closed watch must not cause a busy loop.
        if receiver.changed().await.is_err() {
            pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fedimint_core::config::FederationId;
use fedimint_core::runtime::Instant;
use fedimint_gateway_common::{
    RegisteredProtocol, RegistrationAttempt, RegistrationAttemptResult, RegistrationEndpointStatus,
};
use tokio::sync::RwLock;

/// Lightning module generation whose gateway registration was attempted.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum RegisteredLightningModule {
    /// Legacy Lightning module with gateway-managed announcements.
    Lnv1,
}

/// Key for one independently attempted registration.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct RegistrationKey {
    /// Federation receiving the registration.
    federation_id: FederationId,
    /// Lightning module generation being registered.
    module: RegisteredLightningModule,
    /// Public transport being advertised.
    protocol: RegisteredProtocol,
}

/// Internal retained observation for one registration key.
#[derive(Debug, Clone, Default)]
struct RegistrationObservation {
    /// Begin-order sequence of the newest retained completed attempt.
    last_attempt_sequence: u64,
    /// Completed attempt with the newest begin-order.
    last_attempt: Option<RegistrationAttempt>,
    /// Begin-order sequence and monotonic completion time of the newest
    /// success.
    last_success: Option<(u64, Instant)>,
}

/// Mutable registration observations and leave/rejoin invalidation watermarks.
#[derive(Debug, Default)]
struct RegistrationTrackerState {
    /// Latest observations keyed by federation, module, and transport.
    observations: BTreeMap<RegistrationKey, RegistrationObservation>,
    /// Attempt sequences invalidated when a gateway left a federation.
    cleared_through: BTreeMap<FederationId, u64>,
}

/// Token that orders concurrent registration attempt completions.
#[derive(Debug)]
pub(crate) struct RegistrationAttemptToken {
    /// Registration key being updated.
    key: RegistrationKey,
    /// Monotonically increasing attempt sequence.
    sequence: u64,
}

/// Retains detail-free runtime registration results for public health queries.
#[derive(Debug, Clone, Default)]
pub(crate) struct RegistrationHealthTracker {
    /// Next sequence used to order attempts when they begin.
    next_sequence: Arc<AtomicU64>,
    /// Retained observations and leave/rejoin invalidation watermarks.
    state: Arc<RwLock<RegistrationTrackerState>>,
}

impl RegistrationHealthTracker {
    /// Starts an LNv1 registration attempt and returns its ordering token.
    pub(crate) fn begin_lnv1_attempt(
        &self,
        federation_id: FederationId,
        protocol: RegisteredProtocol,
    ) -> RegistrationAttemptToken {
        RegistrationAttemptToken {
            key: RegistrationKey {
                federation_id,
                module: RegisteredLightningModule::Lnv1,
                protocol,
            },
            sequence: self.next_sequence.fetch_add(1, Ordering::Relaxed) + 1,
        }
    }

    /// Retains a finite result unless an attempt begun later already completed.
    ///
    /// Begin order, rather than completion wall time, defines freshness so a
    /// slow stale request cannot overwrite the result of a newer logical
    /// attempt. Successful TTL is measured from monotonic completion time.
    pub(crate) async fn complete_attempt(
        &self,
        token: RegistrationAttemptToken,
        succeeded: bool,
        completed_wall_time: SystemTime,
        completed_monotonic: Instant,
    ) {
        let mut state = self.state.write().await;
        if state
            .cleared_through
            .get(&token.key.federation_id)
            .is_some_and(|cleared_through| token.sequence <= *cleared_through)
        {
            return;
        }

        let observation = state.observations.entry(token.key).or_default();
        if succeeded
            && observation
                .last_success
                .is_none_or(|(sequence, _)| sequence <= token.sequence)
        {
            observation.last_success = Some((token.sequence, completed_monotonic));
        }

        if observation.last_attempt_sequence <= token.sequence {
            observation.last_attempt_sequence = token.sequence;
            observation.last_attempt = Some(RegistrationAttempt {
                completed_at_unix_secs: completed_wall_time
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                result: if succeeded {
                    RegistrationAttemptResult::Succeeded
                } else {
                    RegistrationAttemptResult::Failed
                },
            });
        }
    }

    /// Returns status for every configured LNv1 public transport.
    pub(crate) async fn lnv1_status(
        &self,
        federation_id: FederationId,
        protocols: impl IntoIterator<Item = RegisteredProtocol>,
        ttl: Duration,
        now: Instant,
    ) -> BTreeMap<RegisteredProtocol, RegistrationEndpointStatus> {
        let state = self.state.read().await;
        protocols
            .into_iter()
            .map(|protocol| {
                let observation = state.observations.get(&RegistrationKey {
                    federation_id,
                    module: RegisteredLightningModule::Lnv1,
                    protocol: protocol.clone(),
                });
                let ttl_remaining = observation.and_then(|observation| {
                    observation.last_success.map(|(_, last_success)| {
                        ttl.saturating_sub(now.saturating_duration_since(last_success))
                            .min(ttl)
                            .as_secs()
                    })
                });
                (
                    protocol,
                    RegistrationEndpointStatus {
                        last_attempt: observation.and_then(|value| value.last_attempt.clone()),
                        advertised_ttl_remaining_secs: ttl_remaining,
                    },
                )
            })
            .collect()
    }

    /// Removes observations after the gateway leaves a federation.
    pub(crate) async fn clear_federation(&self, federation_id: FederationId) {
        let mut state = self.state.write().await;
        state
            .observations
            .retain(|key, _| key.federation_id != federation_id);
        state
            .cleared_through
            .insert(federation_id, self.next_sequence.load(Ordering::Relaxed));
    }
}

#[cfg(test)]
mod tests;

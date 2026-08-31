use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::mem;

use fedimint_connectors::ServerResult;
use fedimint_connectors::error::ServerError;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{NumPeers, PeerId, maybe_add_send_sync};

/// Fedimint query strategy
///
/// Due to federated security model each Fedimint client API call to the
/// Federation might require a different way to process one or more required
/// responses from the Federation members. This trait abstracts away the details
/// of each specific strategy for the generic client Api code.
pub trait QueryStrategy<IR, OR = IR> {
    fn process(&mut self, peer_id: PeerId, response: IR) -> QueryStep<OR>;

    /// Called when a peer's request fails, so a strategy can tell "still
    /// waiting" apart from "will never answer".
    ///
    /// Defaults to [`QueryStep::Continue`], leaving failed peers entirely to
    /// the caller's error accounting, which is what every strategy other than
    /// [`ThresholdAgreement`] wants.
    fn process_error(&mut self, _peer_id: PeerId, _error: &ServerError) -> QueryStep<OR> {
        QueryStep::Continue
    }
}

/// Results from the strategy handling a response from a peer
///
/// Note that the implementation driving the [`QueryStrategy`] returning
/// [`QueryStep`] is responsible from remembering and collecting errors
/// for each peer.
#[derive(Debug)]
pub enum QueryStep<R> {
    /// Retry requests to this peers
    Retry(BTreeSet<PeerId>),
    /// Do nothing yet, keep waiting for requests
    Continue,
    /// Return the successful result
    Success(R),
    /// A non-retryable failure has occurred
    Failure(ServerError),
}

/// Returns when we obtain the first valid responses. RPC call errors or
/// invalid responses are not retried.
pub struct FilterMap<R, T> {
    filter_map: Box<maybe_add_send_sync!(dyn Fn(R) -> ServerResult<T>)>,
}

impl<R, T> FilterMap<R, T> {
    pub fn new(
        filter_map: impl Fn(R) -> ServerResult<T> + MaybeSend + MaybeSync + 'static,
    ) -> Self {
        Self {
            filter_map: Box::new(filter_map),
        }
    }
}

impl<R, T> QueryStrategy<R, T> for FilterMap<R, T> {
    fn process(&mut self, _peer: PeerId, response: R) -> QueryStep<T> {
        match (self.filter_map)(response) {
            Ok(value) => QueryStep::Success(value),
            Err(e) => QueryStep::Failure(e),
        }
    }
}

/// Returns when we obtain a threshold of valid responses. RPC call errors or
/// invalid responses are not retried.
pub struct FilterMapThreshold<R, T> {
    filter_map: Box<maybe_add_send_sync!(dyn Fn(PeerId, R) -> ServerResult<T>)>,
    filtered_responses: BTreeMap<PeerId, T>,
    threshold: usize,
}

impl<R, T> FilterMapThreshold<R, T> {
    pub fn new(
        verifier: impl Fn(PeerId, R) -> ServerResult<T> + MaybeSend + MaybeSync + 'static,
        num_peers: NumPeers,
    ) -> Self {
        Self {
            filter_map: Box::new(verifier),
            filtered_responses: BTreeMap::new(),
            threshold: num_peers.threshold(),
        }
    }
}

impl<R, T> QueryStrategy<R, BTreeMap<PeerId, T>> for FilterMapThreshold<R, T> {
    fn process(&mut self, peer: PeerId, response: R) -> QueryStep<BTreeMap<PeerId, T>> {
        match (self.filter_map)(peer, response) {
            Ok(response) => {
                self.filtered_responses.insert(peer, response);

                if self.filtered_responses.len() == self.threshold {
                    QueryStep::Success(mem::take(&mut self.filtered_responses))
                } else {
                    QueryStep::Continue
                }
            }
            Err(e) => QueryStep::Failure(e),
        }
    }
}

/// Returns when we obtain a threshold of identical responses. Responses are not
/// assumed to be static and may be updated by the peers; on failure to
/// establish consensus with a threshold of responses, we retry the requests.
/// RPC call errors are not retried.
pub struct ThresholdConsensus<R> {
    responses: BTreeMap<PeerId, R>,
    retry: BTreeSet<PeerId>,
    threshold: usize,
}

impl<R> ThresholdConsensus<R> {
    pub fn new(num_peers: NumPeers) -> Self {
        Self {
            responses: BTreeMap::new(),
            retry: BTreeSet::new(),
            threshold: num_peers.threshold(),
        }
    }
}

impl<R: Eq + Clone> QueryStrategy<R> for ThresholdConsensus<R> {
    fn process(&mut self, peer: PeerId, response: R) -> QueryStep<R> {
        self.responses.insert(peer, response.clone());

        if self.responses.values().filter(|r| **r == response).count() == self.threshold {
            return QueryStep::Success(response);
        }

        assert!(self.retry.insert(peer));

        if self.retry.len() == self.threshold {
            QueryStep::Retry(mem::take(&mut self.retry))
        } else {
            QueryStep::Continue
        }
    }
}

#[cfg(test)]
fn dead_peer() -> ServerError {
    ServerError::Connection(anyhow::anyhow!("peer is unreachable"))
}

#[test]
fn threshold_agreement_counts_every_peer() {
    use assert_matches::assert_matches;

    // The case `FilterMapThreshold` gets wrong: peer 0 lags, and the agreement
    // among 1, 2 and 3 only becomes visible once the fourth answer lands. A
    // strategy that stopped at `threshold` responses would have reported a
    // divergence that does not exist.
    let mut agreement = ThresholdAgreement::<u64>::new(NumPeers::from(4));

    assert_matches!(agreement.process(PeerId::from(0), 0), QueryStep::Continue);
    assert_matches!(agreement.process(PeerId::from(1), 1), QueryStep::Continue);
    assert_matches!(agreement.process(PeerId::from(3), 1), QueryStep::Continue);
    assert_matches!(
        agreement.process(PeerId::from(2), 1),
        QueryStep::Success(Ok(1))
    );
}

#[test]
fn threshold_agreement_reports_divergence_once_every_peer_has_answered() {
    use assert_matches::assert_matches;

    let mut agreement = ThresholdAgreement::<u64>::new(NumPeers::from(4));

    assert_matches!(agreement.process(PeerId::from(0), 0), QueryStep::Continue);
    assert_matches!(agreement.process(PeerId::from(1), 1), QueryStep::Continue);
    assert_matches!(agreement.process(PeerId::from(2), 2), QueryStep::Continue);

    let QueryStep::Success(Err(responses)) = agreement.process(PeerId::from(3), 3) else {
        panic!("expected a divergence carrying every response");
    };
    assert_eq!(responses.len(), 4);
}

#[test]
fn threshold_agreement_does_not_wait_on_a_peer_that_errored() {
    use assert_matches::assert_matches;

    // A failed peer completes the picture just as a response does, so the
    // divergence is reported rather than waiting on an answer that is never
    // coming - the hang this strategy exists to avoid.
    let mut agreement = ThresholdAgreement::<u64>::new(NumPeers::from(4));

    assert_matches!(agreement.process(PeerId::from(0), 0), QueryStep::Continue);
    assert_matches!(agreement.process(PeerId::from(1), 1), QueryStep::Continue);
    assert_matches!(agreement.process(PeerId::from(2), 1), QueryStep::Continue);

    let QueryStep::Success(Err(responses)) = agreement.process_error(PeerId::from(3), &dead_peer())
    else {
        panic!("expected a divergence once every peer has answered");
    };
    assert_eq!(responses.len(), 3);
}

#[test]
fn threshold_agreement_defers_to_peer_errors_when_too_few_answered() {
    use assert_matches::assert_matches;

    // Two of four unreachable leaves fewer responses than the threshold. The
    // useful complaint is that peers are down, which the caller reports from
    // its own error accounting, so stay quiet.
    let mut agreement = ThresholdAgreement::<u64>::new(NumPeers::from(4));

    assert_matches!(agreement.process(PeerId::from(0), 0), QueryStep::Continue);
    assert_matches!(agreement.process(PeerId::from(1), 1), QueryStep::Continue);
    assert_matches!(
        agreement.process_error(PeerId::from(2), &dead_peer()),
        QueryStep::Continue
    );
    assert_matches!(
        agreement.process_error(PeerId::from(3), &dead_peer()),
        QueryStep::Continue
    );
}

/// Returns the response a threshold of peers agree on, or - when they do not
/// converge - every answer received, as `Err`.
///
/// Like [`ThresholdConsensus`] it counts identical responses across *all*
/// peers rather than the first `threshold` to reply, so one lagging peer
/// cannot mask an agreement that exists among the others.
///
/// Unlike it, a disagreement is never retried. Values worth querying this way
/// are a pure function of the ordered consensus log, so a peer that has fallen
/// behind never converges, and re-requesting it renews the transport timeout
/// indefinitely. Asking each peer exactly once is what bounds the call.
pub struct ThresholdAgreement<R> {
    responses: BTreeMap<PeerId, R>,
    errors: usize,
    threshold: usize,
    total: usize,
}

impl<R> ThresholdAgreement<R> {
    pub fn new(num_peers: NumPeers) -> Self {
        Self {
            responses: BTreeMap::new(),
            errors: 0,
            threshold: num_peers.threshold(),
            total: num_peers.total(),
        }
    }

    /// Every peer has answered one way or the other without any value reaching
    /// a threshold, so waiting longer cannot help.
    fn diverged(&mut self) -> Option<QueryStep<Result<R, BTreeMap<PeerId, R>>>> {
        if self.responses.len() + self.errors < self.total {
            return None;
        }

        // Below a threshold of responses the useful complaint is that too few
        // peers answered, not that they disagreed. Stay quiet and let the
        // caller report the peer errors it collected.
        if self.responses.len() < self.threshold {
            return None;
        }

        Some(QueryStep::Success(Err(mem::take(&mut self.responses))))
    }
}

impl<R: Eq + Clone> QueryStrategy<R, Result<R, BTreeMap<PeerId, R>>> for ThresholdAgreement<R> {
    fn process(&mut self, peer: PeerId, response: R) -> QueryStep<Result<R, BTreeMap<PeerId, R>>> {
        self.responses.insert(peer, response.clone());

        if self.responses.values().filter(|r| **r == response).count() == self.threshold {
            return QueryStep::Success(Ok(response));
        }

        self.diverged().unwrap_or(QueryStep::Continue)
    }

    fn process_error(
        &mut self,
        _peer: PeerId,
        _error: &ServerError,
    ) -> QueryStep<Result<R, BTreeMap<PeerId, R>>> {
        self.errors += 1;

        self.diverged().unwrap_or(QueryStep::Continue)
    }
}

#[test]
fn test_threshold_consensus() {
    use assert_matches::assert_matches;

    let mut consensus = ThresholdConsensus::<u64>::new(NumPeers::from(4));

    assert_matches!(consensus.process(PeerId::from(0), 1), QueryStep::Continue);
    assert_matches!(consensus.process(PeerId::from(1), 1), QueryStep::Continue);
    assert_matches!(consensus.process(PeerId::from(2), 0), QueryStep::Retry(..));

    assert_matches!(consensus.process(PeerId::from(0), 1), QueryStep::Continue);
    assert_matches!(consensus.process(PeerId::from(1), 1), QueryStep::Continue);
    assert_matches!(consensus.process(PeerId::from(2), 1), QueryStep::Success(1));
}

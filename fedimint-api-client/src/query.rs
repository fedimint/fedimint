use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::future::{Future, ready};
use std::mem;
use std::pin::Pin;

use fedimint_connectors::ServerResult;
use fedimint_connectors::error::ServerError;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{NumPeers, PeerId, maybe_add_send, maybe_add_send_sync};

/// Fedimint query strategy
///
/// Due to federated security model each Fedimint client API call to the
/// Federation might require a different way to process one or more required
/// responses from the Federation members. This trait abstracts away the details
/// of each specific strategy for the generic client Api code.
pub trait QueryStrategy<IR, OR = IR> {
    /// Processes a peer's response.
    ///
    /// A strategy that verifies responses awaits the verification, so a heavy
    /// one can run off the async workers.
    fn process(
        &mut self,
        peer_id: PeerId,
        response: IR,
    ) -> impl Future<Output = QueryStep<OR>> + MaybeSend;

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

impl<R, T: MaybeSend> QueryStrategy<R, T> for FilterMap<R, T> {
    fn process(
        &mut self,
        _peer: PeerId,
        response: R,
    ) -> impl Future<Output = QueryStep<T>> + MaybeSend {
        ready(match (self.filter_map)(response) {
            Ok(value) => QueryStep::Success(value),
            Err(e) => QueryStep::Failure(e),
        })
    }
}

/// Returns when we obtain a threshold of valid responses. RPC call errors or
/// invalid responses are not retried.
pub struct FilterMapThreshold<R, T> {
    filter_map: Box<maybe_add_send_sync!(dyn Fn(PeerId, R) -> FilterMapFuture<T>)>,
    filtered_responses: BTreeMap<PeerId, T>,
    threshold: usize,
}

type FilterMapFuture<T> = Pin<Box<maybe_add_send!(dyn Future<Output = ServerResult<T>>)>>;

impl<R, T> FilterMapThreshold<R, T> {
    /// The verifier runs once per response and is awaited, so pairings and
    /// other heavy checks can go on the blocking pool.
    pub fn new<Fut>(
        verifier: impl Fn(PeerId, R) -> Fut + MaybeSend + MaybeSync + 'static,
        num_peers: NumPeers,
    ) -> Self
    where
        Fut: Future<Output = ServerResult<T>> + MaybeSend + 'static,
    {
        Self {
            filter_map: Box::new(move |peer, response| Box::pin(verifier(peer, response))),
            filtered_responses: BTreeMap::new(),
            threshold: num_peers.threshold(),
        }
    }
}

impl<R: MaybeSend, T: MaybeSend> QueryStrategy<R, BTreeMap<PeerId, T>>
    for FilterMapThreshold<R, T>
{
    async fn process(&mut self, peer: PeerId, response: R) -> QueryStep<BTreeMap<PeerId, T>> {
        match (self.filter_map)(peer, response).await {
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

impl<R: Eq + Clone + MaybeSend> QueryStrategy<R> for ThresholdConsensus<R> {
    fn process(
        &mut self,
        peer: PeerId,
        response: R,
    ) -> impl Future<Output = QueryStep<R>> + MaybeSend {
        self.responses.insert(peer, response.clone());

        if self.responses.values().filter(|r| **r == response).count() == self.threshold {
            return ready(QueryStep::Success(response));
        }

        assert!(self.retry.insert(peer));

        ready(if self.retry.len() == self.threshold {
            QueryStep::Retry(mem::take(&mut self.retry))
        } else {
            QueryStep::Continue
        })
    }
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

impl<R: Eq + Clone + MaybeSend> QueryStrategy<R, Result<R, BTreeMap<PeerId, R>>>
    for ThresholdAgreement<R>
{
    fn process(
        &mut self,
        peer: PeerId,
        response: R,
    ) -> impl Future<Output = QueryStep<Result<R, BTreeMap<PeerId, R>>>> + MaybeSend {
        self.responses.insert(peer, response.clone());

        if self.responses.values().filter(|r| **r == response).count() == self.threshold {
            return ready(QueryStep::Success(Ok(response)));
        }

        ready(self.diverged().unwrap_or(QueryStep::Continue))
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

#[cfg(test)]
mod tests;

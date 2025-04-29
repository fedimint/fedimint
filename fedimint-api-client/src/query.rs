use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::mem;

use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{maybe_add_send_sync, NumPeers, PeerId};

use crate::api::{PeerError, PeerResult};

/// Fedimint query strategy
///
/// Due to federated security model each Fedimint client API call to the
/// Federation might require a different way to process one or more required
/// responses from the Federation members. This trait abstracts away the details
/// of each specific strategy for the generic client Api code.
pub trait QueryStrategy<IR, OR = IR> {
    fn process(&mut self, peer_id: PeerId, response: IR) -> QueryStep<OR>;
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
    Failure(PeerError),
}

/// Returns when we obtain the first valid responses. RPC call errors or
/// invalid responses are not retried.
pub struct FilterMap<R, T> {
    filter_map: Box<maybe_add_send_sync!(dyn Fn(R) -> PeerResult<T>)>,
}

impl<R, T> FilterMap<R, T> {
    pub fn new(filter_map: impl Fn(R) -> PeerResult<T> + MaybeSend + MaybeSync + 'static) -> Self {
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
    filter_map: Box<maybe_add_send_sync!(dyn Fn(PeerId, R) -> PeerResult<T>)>,
    filtered_responses: BTreeMap<PeerId, T>,
    threshold: usize,
}

impl<R, T> FilterMapThreshold<R, T> {
    pub fn new(
        verifier: impl Fn(PeerId, R) -> PeerResult<T> + MaybeSend + MaybeSync + 'static,
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

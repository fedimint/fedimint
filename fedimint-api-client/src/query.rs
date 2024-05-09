use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Debug;
use std::mem;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, format_err};
use fedimint_core::module::{
    ApiVersion, SupportedApiVersionsSummary, SupportedCoreApiVersions, SupportedModuleApiVersions,
};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::time::now;
use fedimint_core::{maybe_add_send_sync, NumPeers, NumPeersExt, PeerId};
use itertools::Itertools;

use crate::api::{self, ApiVersionSet, PeerError, PeerResult};

/// Fedimint query strategy
///
/// Due to federated security model each Fedimint client API call to the
/// Federation might require a different way to process one or more required
/// responses from the Federation members. This trait abstracts away the details
/// of each specific strategy for the generic client Api code.
pub trait QueryStrategy<IR, OR = IR> {
    /// Should requests for this strategy have specific timeouts?
    fn request_timeout(&self) -> Option<Duration> {
        None
    }
    /// Process a `response` from the `peer_id` and return query steps to take
    fn process(&mut self, peer_id: PeerId, response: api::PeerResult<IR>) -> QueryStep<OR>;

    /// There's no more peers to query, return query steps to take (typically
    /// failure)
    fn exhausted(&mut self) -> QueryStep<OR>;
}

/// Results from the strategy handling a response from a peer
///
/// Note that the implementation driving the [`QueryStrategy`] returning
/// [`QueryStep`] is responsible from remembering and collecting errors
/// for each peer.
#[derive(Debug)]
pub enum QueryStep<R> {
    /// Retry request to this peer
    Retry(BTreeSet<PeerId>),
    /// Do nothing yet, keep waiting for requests
    Continue,
    /// Return the successful result
    Success(R),
    /// Fail the whole request
    Failure {
        general: Option<anyhow::Error>,
        peers: BTreeMap<PeerId, PeerError>,
    },
}

struct ErrorStrategy {
    errors: BTreeMap<PeerId, PeerError>,
    num_peers: NumPeers,
}

impl ErrorStrategy {
    pub fn new(num_peers: NumPeers) -> Self {
        assert!(num_peers.threshold() > 0);

        Self {
            errors: BTreeMap::new(),
            num_peers,
        }
    }

    fn format_errors(&self) -> String {
        use std::fmt::Write;
        self.errors
            .iter()
            .fold(String::new(), |mut s, (peer_id, e)| {
                if !s.is_empty() {
                    write!(s, ", ").expect("can't fail");
                }
                write!(s, "peer-{peer_id}: {e}").expect("can't fail");

                s
            })
    }

    pub fn process<R>(&mut self, peer: PeerId, error: PeerError) -> QueryStep<R> {
        assert!(self.errors.insert(peer, error).is_none());

        let call_error_count = self.errors.iter().filter(|(_, e)| e.is_call_err()).count();
        let non_call_error_count = self.errors.len() - call_error_count;
        if non_call_error_count == self.num_peers.one_honest() {
            // If there enough non-application errors that there's no way to get consensus,
            // there's no reason to continue.
            QueryStep::Failure {
                general: Some(anyhow!(
                    "Received {} out of {} non-call errors from peers: {}",
                    self.num_peers.threshold(),
                    self.num_peers,
                    self.format_errors()
                )),
                peers: mem::take(&mut self.errors),
            }
        } else if call_error_count == self.num_peers.threshold() {
            // For a call-errors to surface as a federation-level, it needs get a threshold
            // of responses being call-errors.
            QueryStep::Failure {
                general: Some(anyhow!(
                    "Received {} out of {} call errors from peers: {}",
                    self.num_peers.threshold(),
                    self.num_peers,
                    self.format_errors()
                )),
                peers: mem::take(&mut self.errors),
            }
        } else {
            QueryStep::Continue
        }
    }

    fn exhausted<R>(&mut self) -> QueryStep<R> {
        // It's possible that a combination of results, non-call and call errors doesn't
        // reach the threshold anywhere. In that case, just return all existing
        // errors.
        QueryStep::Failure {
            general: Some(anyhow!(
                "Exhausted {} peers without reaching result or conclusive errors from peers: {}",
                self.num_peers,
                self.format_errors()
            )),
            peers: mem::take(&mut self.errors),
        }
    }
}

/// Returns the first valid response. The response of a peer is
/// assumed to be final, hence this query strategy does not implement retry
/// logic.
pub struct FilterMap<R, T> {
    filter_map: Box<maybe_add_send_sync!(dyn Fn(R) -> anyhow::Result<T>)>,
    error_strategy: ErrorStrategy,
}

impl<R, T> FilterMap<R, T> {
    /// Strategy for returning first response that is verifiable (typically with
    /// a signature)
    pub fn new(
        filter_map: impl Fn(R) -> anyhow::Result<T> + MaybeSend + MaybeSync + 'static,
        total_peers: usize,
    ) -> Self {
        Self {
            filter_map: Box::new(filter_map),
            error_strategy: ErrorStrategy::new(NumPeers::from(total_peers)),
        }
    }
}

impl<R: Debug + Eq + Clone, T> QueryStrategy<R, T> for FilterMap<R, T> {
    fn process(&mut self, peer: PeerId, result: PeerResult<R>) -> QueryStep<T> {
        match result {
            Ok(response) => match (self.filter_map)(response) {
                Ok(value) => QueryStep::Success(value),
                Err(error) => self
                    .error_strategy
                    .process(peer, PeerError::InvalidResponse(error.to_string())),
            },
            Err(error) => self.error_strategy.process(peer, error),
        }
    }
    fn exhausted(&mut self) -> QueryStep<T> {
        self.error_strategy.exhausted()
    }
}

/// Returns when a threshold of valid responses. The response of a peer is
/// assumed to be final, hence this query strategy does not implement retry
/// logic.
pub struct FilterMapThreshold<R, T> {
    filter_map: Box<maybe_add_send_sync!(dyn Fn(PeerId, R) -> anyhow::Result<T>)>,
    error_strategy: ErrorStrategy,
    filtered_responses: BTreeMap<PeerId, T>,
    threshold: usize,
}

impl<R, T> FilterMapThreshold<R, T> {
    pub fn new(
        verifier: impl Fn(PeerId, R) -> anyhow::Result<T> + MaybeSend + MaybeSync + 'static,
        total_peers: usize,
    ) -> Self {
        let max_evil = (total_peers - 1) / 3;
        let threshold = total_peers - max_evil;

        Self {
            filter_map: Box::new(verifier),
            error_strategy: ErrorStrategy::new(NumPeers::from(total_peers)),
            filtered_responses: BTreeMap::new(),
            threshold,
        }
    }
}

impl<R: Eq + Clone + Debug, T> QueryStrategy<R, BTreeMap<PeerId, T>> for FilterMapThreshold<R, T> {
    fn process(&mut self, peer: PeerId, result: PeerResult<R>) -> QueryStep<BTreeMap<PeerId, T>> {
        match result {
            Ok(response) => match (self.filter_map)(peer, response) {
                Ok(response) => {
                    self.filtered_responses.insert(peer, response);

                    if self.filtered_responses.len() == self.threshold {
                        QueryStep::Success(mem::take(&mut self.filtered_responses))
                    } else {
                        QueryStep::Continue
                    }
                }
                Err(error) => self
                    .error_strategy
                    .process(peer, PeerError::InvalidResponse(error.to_string())),
            },
            Err(error) => self.error_strategy.process(peer, error),
        }
    }
    fn exhausted(&mut self) -> QueryStep<BTreeMap<PeerId, T>> {
        self.error_strategy.exhausted()
    }
}

/// Returns when we obtain a threshold of identical responses
pub struct ThresholdConsensus<R> {
    error_strategy: ErrorStrategy,
    responses: BTreeMap<PeerId, R>,
    retry: BTreeSet<PeerId>,
    threshold: usize,
}

impl<R> ThresholdConsensus<R> {
    pub fn new(total_peers: usize) -> Self {
        let max_evil = (total_peers - 1) / 3;
        let threshold = total_peers - max_evil;

        Self {
            error_strategy: ErrorStrategy::new(NumPeers::from(total_peers)),
            responses: BTreeMap::new(),
            retry: BTreeSet::new(),
            threshold,
        }
    }
}

impl<R: Eq> ThresholdConsensus<R> {
    /// Get the most common response that has been processed so far. If there is
    /// a tie between two values, the value picked is arbitrary and stability
    /// between calls is not guaranteed.
    fn get_most_common_response(&self) -> Option<&R> {
        // TODO: This implementation scales poorly as `self.responses` increases (n^2)
        self.responses
            .values()
            .max_by_key(|response| self.responses.values().filter(|r| r == response).count())
    }
}

impl<R: Eq + Clone + Debug> QueryStrategy<R> for ThresholdConsensus<R> {
    fn process(&mut self, peer: PeerId, result: api::PeerResult<R>) -> QueryStep<R> {
        match result {
            Ok(response) => {
                self.responses.insert(peer, response);
                assert!(self.retry.insert(peer));

                if let Some(most_common_response) = self.get_most_common_response() {
                    let count = self
                        .responses
                        .values()
                        .filter(|r| r == &most_common_response)
                        .count();

                    if count >= self.threshold {
                        return QueryStep::Success(most_common_response.clone());
                    }
                }

                if self.retry.len() == self.threshold {
                    QueryStep::Retry(mem::take(&mut self.retry))
                } else {
                    QueryStep::Continue
                }
            }
            Err(error) => self.error_strategy.process(peer, error),
        }
    }
    fn exhausted(&mut self) -> QueryStep<R> {
        self.error_strategy.exhausted()
    }
}

/// Returns the deduplicated union of a threshold of responses; elements are
/// in descending order by the number of duplications across different peers.
pub struct UnionResponses<R> {
    error_strategy: ErrorStrategy,
    responses: HashMap<PeerId, Vec<R>>,
    threshold: usize,
}

impl<R> UnionResponses<R> {
    pub fn new(total_peers: NumPeers) -> Self {
        Self {
            error_strategy: ErrorStrategy::new(total_peers),
            responses: HashMap::new(),
            threshold: total_peers.threshold(),
        }
    }
}

impl<R: Debug + Eq + Clone> QueryStrategy<Vec<R>> for UnionResponses<R> {
    fn process(&mut self, peer: PeerId, result: PeerResult<Vec<R>>) -> QueryStep<Vec<R>> {
        match result {
            Ok(response) => {
                assert!(self.responses.insert(peer, response).is_none());

                if self.responses.len() == self.threshold {
                    let mut union = self
                        .responses
                        .values()
                        .flatten()
                        .dedup()
                        .cloned()
                        .collect::<Vec<R>>();

                    union.sort_by_cached_key(|r| {
                        self.responses
                            .values()
                            .filter(|response| !response.contains(r))
                            .count()
                    });

                    QueryStep::Success(union)
                } else {
                    QueryStep::Continue
                }
            }
            Err(error) => self.error_strategy.process(peer, error),
        }
    }

    fn exhausted(&mut self) -> QueryStep<Vec<R>> {
        self.error_strategy.exhausted()
    }
}

/// Returns the deduplicated union of `required` number of responses
///
/// Unlike [`UnionResponses`], it works with single values, not `Vec`s.
pub struct UnionResponsesSingle<R> {
    error_strategy: ErrorStrategy,
    responses: HashSet<PeerId>,
    union: Vec<R>,
    threshold: usize,
}

impl<R> UnionResponsesSingle<R> {
    pub fn new(total_peers: NumPeers) -> Self {
        Self {
            error_strategy: ErrorStrategy::new(total_peers),
            responses: HashSet::new(),
            union: vec![],
            threshold: total_peers.threshold(),
        }
    }
}

impl<R: Debug + Eq + Clone> QueryStrategy<R, Vec<R>> for UnionResponsesSingle<R> {
    fn process(&mut self, peer: PeerId, result: api::PeerResult<R>) -> QueryStep<Vec<R>> {
        match result {
            Ok(response) => {
                if !self.union.contains(&response) {
                    self.union.push(response);
                }

                assert!(self.responses.insert(peer));

                if self.responses.len() == self.threshold {
                    QueryStep::Success(mem::take(&mut self.union))
                } else {
                    QueryStep::Continue
                }
            }
            Err(error) => self.error_strategy.process(peer, error),
        }
    }

    fn exhausted(&mut self) -> QueryStep<Vec<R>> {
        self.error_strategy.exhausted()
    }
}

/// Query strategy that returns when enough peers responded or a deadline passed
pub struct ThresholdOrDeadline<R> {
    deadline: SystemTime,
    threshold: usize,
    responses: BTreeMap<PeerId, R>,
}

impl<R> ThresholdOrDeadline<R> {
    pub fn new(threshold: usize, deadline: SystemTime) -> Self {
        Self {
            deadline,
            threshold,
            responses: BTreeMap::default(),
        }
    }
}

impl<R> QueryStrategy<R, BTreeMap<PeerId, R>> for ThresholdOrDeadline<R> {
    fn process(
        &mut self,
        peer: PeerId,
        result: api::PeerResult<R>,
    ) -> QueryStep<BTreeMap<PeerId, R>> {
        match result {
            Ok(response) => {
                assert!(self.responses.insert(peer, response).is_none());

                if self.threshold <= self.responses.len() || self.deadline <= now() {
                    QueryStep::Success(mem::take(&mut self.responses))
                } else {
                    QueryStep::Continue
                }
            }
            // we rely on retries and timeouts to detect a deadline passing
            Err(_) => {
                if self.deadline <= now() {
                    QueryStep::Success(mem::take(&mut self.responses))
                } else {
                    QueryStep::Retry(BTreeSet::from([peer]))
                }
            }
        }
    }

    fn exhausted(&mut self) -> QueryStep<BTreeMap<PeerId, R>> {
        QueryStep::Success(mem::take(&mut self.responses))
    }
}

/// Query for supported api versions from all the guardians (with a deadline)
/// and calculate the best versions to use for each component (core + modules).
pub struct DiscoverApiVersionSet {
    inner: ThresholdOrDeadline<SupportedApiVersionsSummary>,
    client_versions: SupportedApiVersionsSummary,
}

impl DiscoverApiVersionSet {
    pub fn new(
        threshold: usize,
        deadline: SystemTime,
        client_versions: SupportedApiVersionsSummary,
    ) -> Self {
        Self {
            inner: ThresholdOrDeadline::new(threshold, deadline),
            client_versions,
        }
    }

    /// Convert the `step` return by `inner` to own step
    fn convert_inner_step(
        &mut self,
        step: QueryStep<BTreeMap<PeerId, SupportedApiVersionsSummary>>,
    ) -> QueryStep<ApiVersionSet> {
        match step {
            QueryStep::Success(o) => {
                match discover_common_api_versions_set(&self.client_versions, o) {
                    Ok(o) => QueryStep::Success(o),
                    Err(e) => QueryStep::Failure {
                        general: Some(e),
                        peers: BTreeMap::new(),
                    },
                }
            }
            QueryStep::Retry(v) => QueryStep::Retry(v),
            QueryStep::Continue => QueryStep::Continue,
            QueryStep::Failure { general, peers } => QueryStep::Failure { general, peers },
        }
    }
}

impl QueryStrategy<SupportedApiVersionsSummary, ApiVersionSet> for DiscoverApiVersionSet {
    fn request_timeout(&self) -> Option<Duration> {
        Some(
            self.inner
                .deadline
                .duration_since(fedimint_core::time::now())
                .unwrap_or(Duration::ZERO),
        )
    }

    fn process(
        &mut self,
        peer: PeerId,
        result: api::PeerResult<SupportedApiVersionsSummary>,
    ) -> QueryStep<ApiVersionSet> {
        let step = self.inner.process(peer, result);
        self.convert_inner_step(step)
    }

    fn exhausted(&mut self) -> QueryStep<ApiVersionSet> {
        let step = self.inner.exhausted();
        self.convert_inner_step(step)
    }
}

fn discover_common_core_api_version(
    client_versions: &SupportedCoreApiVersions,
    peer_versions: BTreeMap<PeerId, SupportedCoreApiVersions>,
) -> Option<ApiVersion> {
    let mut best_major = None;
    let mut best_major_peer_num = 0;

    // Find major api version with highest peer number supporting it
    for client_api_version in &client_versions.api {
        let peers_compatible_num = peer_versions
            .values()
            .filter_map(|supported_versions| {
                supported_versions
                    .get_minor_api_version(client_versions.core_consensus, client_api_version.major)
            })
            .filter(|peer_minor| client_api_version.minor <= *peer_minor)
            .count();

        if best_major_peer_num < peers_compatible_num {
            best_major = Some(client_api_version);
            best_major_peer_num = peers_compatible_num;
        }
    }

    // Adjust the minor version to the smallest supported by all matching peers
    best_major.map(
        |ApiVersion {
             major: best_major,
             minor: best_major_minor,
         }| ApiVersion {
            major: best_major,
            minor: peer_versions
                .values()
                .filter_map(|supported| {
                    supported.get_minor_api_version(client_versions.core_consensus, best_major)
                })
                .filter(|peer_minor| best_major_minor <= *peer_minor)
                .min()
                .expect("We must have at least one"),
        },
    )
}

#[test]
fn discover_common_core_api_version_sanity() {
    use fedimint_core::module::MultiApiVersion;

    let core_consensus = fedimint_core::module::CoreConsensusVersion::new(0, 0);
    let client_versions = SupportedCoreApiVersions {
        core_consensus,
        api: MultiApiVersion::try_from_iter([
            ApiVersion { major: 2, minor: 3 },
            ApiVersion { major: 3, minor: 1 },
        ])
        .unwrap(),
    };

    assert!(discover_common_core_api_version(&client_versions, BTreeMap::from([])).is_none());
    assert_eq!(
        discover_common_core_api_version(
            &client_versions,
            BTreeMap::from([(
                PeerId::from(0),
                SupportedCoreApiVersions {
                    core_consensus: fedimint_core::module::CoreConsensusVersion::new(0, 0),
                    api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 3 }])
                        .unwrap(),
                }
            )])
        ),
        Some(ApiVersion { major: 2, minor: 3 })
    );
    assert_eq!(
        discover_common_core_api_version(
            &client_versions,
            BTreeMap::from([(
                PeerId::from(0),
                SupportedCoreApiVersions {
                    core_consensus: fedimint_core::module::CoreConsensusVersion::new(0, 1), /* different minor consensus version, we don't care */
                    api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 3 }])
                        .unwrap(),
                }
            )])
        ),
        Some(ApiVersion { major: 2, minor: 3 })
    );
    assert_eq!(
        discover_common_core_api_version(
            &client_versions,
            BTreeMap::from([(
                PeerId::from(0),
                SupportedCoreApiVersions {
                    core_consensus: fedimint_core::module::CoreConsensusVersion::new(1, 0), /* wrong consensus version */
                    api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 4 }])
                        .unwrap(),
                }
            )])
        ),
        None
    );
    assert_eq!(
        discover_common_core_api_version(
            &client_versions,
            BTreeMap::from([
                (
                    PeerId::from(0),
                    SupportedCoreApiVersions {
                        core_consensus,
                        api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 2 }])
                            .unwrap(),
                    }
                ),
                (
                    PeerId::from(1),
                    SupportedCoreApiVersions {
                        core_consensus,
                        api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 1 }])
                            .unwrap(),
                    }
                ),
                (
                    PeerId::from(1),
                    SupportedCoreApiVersions {
                        core_consensus,
                        api: MultiApiVersion::try_from_iter([ApiVersion { major: 3, minor: 1 }])
                            .unwrap(),
                    }
                )
            ])
        ),
        Some(ApiVersion { major: 3, minor: 1 })
    );
    assert_eq!(
        discover_common_core_api_version(
            &client_versions,
            BTreeMap::from([
                (
                    PeerId::from(0),
                    SupportedCoreApiVersions {
                        core_consensus,
                        api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 4 }])
                            .unwrap(),
                    }
                ),
                (
                    PeerId::from(1),
                    SupportedCoreApiVersions {
                        core_consensus,
                        api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 5 }])
                            .unwrap(),
                    }
                ),
            ])
        ),
        Some(ApiVersion { major: 2, minor: 4 })
    );
}

fn discover_common_module_api_version(
    client_versions: &SupportedModuleApiVersions,
    peer_versions: BTreeMap<PeerId, SupportedModuleApiVersions>,
) -> Option<ApiVersion> {
    let mut best_major = None;
    let mut best_major_peer_num = 0;

    // Find major api version with highest peer number supporting it
    for client_api_version in &client_versions.api {
        let peers_compatible_num = peer_versions
            .values()
            .filter_map(|supported_versions| {
                supported_versions.get_minor_api_version(
                    client_versions.core_consensus,
                    client_versions.module_consensus,
                    client_api_version.major,
                )
            })
            .filter(|peer_minor| client_api_version.minor <= *peer_minor)
            .count();

        if best_major_peer_num < peers_compatible_num {
            best_major = Some(client_api_version);
            best_major_peer_num = peers_compatible_num;
        }
    }

    // Adjust the minor version to the smallest supported by all matching peers
    best_major.map(
        |ApiVersion {
             major: best_major,
             minor: best_major_minor,
         }| ApiVersion {
            major: best_major,
            minor: peer_versions
                .values()
                .filter_map(|supported| {
                    supported.get_minor_api_version(
                        client_versions.core_consensus,
                        client_versions.module_consensus,
                        best_major,
                    )
                })
                .filter(|peer_minor| best_major_minor <= *peer_minor)
                .min()
                .expect("We must have at least one"),
        },
    )
}

fn discover_common_api_versions_set(
    client_versions: &SupportedApiVersionsSummary,
    peer_versions: BTreeMap<PeerId, SupportedApiVersionsSummary>,
) -> anyhow::Result<ApiVersionSet> {
    Ok(ApiVersionSet {
        core: discover_common_core_api_version(
            &client_versions.core,
            peer_versions
                .iter()
                .map(|(peer_id, peer_supported_api_versions)| {
                    (*peer_id, peer_supported_api_versions.core.clone())
                })
                .collect(),
        )
        .ok_or_else(|| format_err!("Could not find a common core API version"))?,
        modules: client_versions
            .modules
            .iter()
            .filter_map(
                |(module_instance_id, client_supported_module_api_versions)| {
                    let discover_common_module_api_version = discover_common_module_api_version(
                        client_supported_module_api_versions,
                        peer_versions
                            .iter()
                            .filter_map(|(peer_id, peer_supported_api_versions_summary)| {
                                peer_supported_api_versions_summary
                                    .modules
                                    .get(module_instance_id)
                                    .map(|versions| (*peer_id, versions.clone()))
                            })
                            .collect(),
                    );
                    discover_common_module_api_version.map(|v| (*module_instance_id, v))
                },
            )
            .collect(),
    })
}

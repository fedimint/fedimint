use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Debug;
use std::mem;
use std::time::{Duration, SystemTime};

use anyhow::format_err;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::time::now;
use fedimint_core::{maybe_add_send_sync, PeerId};

use crate::api::{self, ApiVersionSet, MemberError};
use crate::module::{
    ApiVersion, SupportedApiVersionsSummary, SupportedCoreApiVersions, SupportedModuleApiVersions,
};

/// Returns a result from the first responding peer
pub struct TrustAllPeers;

impl<R> QueryStrategy<R> for TrustAllPeers {
    fn process(&mut self, peer: PeerId, result: api::MemberResult<R>) -> QueryStep<R> {
        match result {
            Ok(o) => QueryStep::Success(o),
            Err(e) => QueryStep::FailMembers(BTreeMap::from([(peer, e)])),
        }
    }
}

/// Returns first response with a valid signature
pub struct VerifiableResponse<R> {
    verifier: Box<maybe_add_send_sync!(dyn Fn(&R) -> bool)>,
    allow_consensus_fallback: bool,
    current: CurrentConsensus<R>,
}

impl<R> VerifiableResponse<R> {
    /// Strategy for returning first response that is verifiable (typically with
    /// a signature)
    ///
    /// * `required`: How many responses until a failure or success is returned
    /// * `allow_consensus_fallback`: Returns a success if cannot verify but
    ///   `required` agree
    /// * `verifier`: Function that verifies the data with the public key
    pub fn new(
        total_peers: usize,
        allow_consensus_fallback: bool,
        verifier: impl Fn(&R) -> bool + MaybeSend + MaybeSync + 'static,
    ) -> Self {
        Self {
            verifier: Box::new(verifier),
            allow_consensus_fallback,
            current: CurrentConsensus::new(total_peers),
        }
    }
}

impl<R: Debug + Eq + Clone> QueryStrategy<R> for VerifiableResponse<R> {
    fn process(&mut self, peer: PeerId, result: api::MemberResult<R>) -> QueryStep<R> {
        match result {
            Ok(result) if (self.verifier)(&result) => QueryStep::Success(result),
            Ok(result) => {
                if self.allow_consensus_fallback {
                    self.current.process(peer, Ok(result))
                } else {
                    self.current.process(
                        peer,
                        Err(MemberError::InvalidResponse(
                            "Invalid signature".to_string(),
                        )),
                    )
                }
            }
            error => self.current.process(peer, error),
        }
    }
}

/// Returns the deduplicated union of `required` number of responses
pub struct UnionResponses<R> {
    responses: HashSet<PeerId>,
    existing_results: Vec<R>,
    current: CurrentConsensus<Vec<R>>,
    threshold: usize,
}

impl<R> UnionResponses<R> {
    pub fn new(total_peers: usize) -> Self {
        let max_evil = (total_peers - 1) / 3;
        let threshold = total_peers - max_evil;

        Self {
            responses: HashSet::new(),
            existing_results: vec![],
            current: CurrentConsensus::new(total_peers),
            threshold,
        }
    }
}

impl<R: Debug + Eq + Clone> QueryStrategy<Vec<R>> for UnionResponses<R> {
    fn process(&mut self, peer: PeerId, results: api::MemberResult<Vec<R>>) -> QueryStep<Vec<R>> {
        if let Ok(results) = results {
            for new_result in results {
                if !self.existing_results.iter().any(|r| r == &new_result) {
                    self.existing_results.push(new_result);
                }
            }

            self.responses.insert(peer);

            if self.responses.len() >= self.threshold {
                QueryStep::Success(mem::take(&mut self.existing_results))
            } else {
                QueryStep::Continue
            }
        } else {
            // handle error case using the CurrentConsensus method
            self.current.process(peer, results)
        }
    }
}

/// Returns the deduplicated union of `required` number of responses
///
/// Unlike [`UnionResponses`], it works with single values, not `Vec`s.
/// TODO: Should we make `UnionResponses` a wrapper around this one?
pub struct UnionResponsesSingle<R> {
    responses: HashSet<PeerId>,
    existing_results: Vec<R>,
    current: CurrentConsensus<Vec<R>>,
    threshold: usize,
}

impl<R> UnionResponsesSingle<R> {
    pub fn new(total_peers: usize) -> Self {
        let max_evil = (total_peers - 1) / 3;
        let threshold = total_peers - max_evil;

        Self {
            responses: HashSet::new(),
            existing_results: vec![],
            current: CurrentConsensus::new(total_peers),
            threshold,
        }
    }
}

impl<R: Debug + Eq + Clone> QueryStrategy<R, Vec<R>> for UnionResponsesSingle<R> {
    fn process(&mut self, peer: PeerId, result: api::MemberResult<R>) -> QueryStep<Vec<R>> {
        match result {
            Ok(new_result) => {
                if !self.existing_results.iter().any(|r| r == &new_result) {
                    self.existing_results.push(new_result);
                }

                self.responses.insert(peer);

                if self.responses.len() >= self.threshold {
                    QueryStep::Success(mem::take(&mut self.existing_results))
                } else {
                    QueryStep::Continue
                }
            }
            Err(e) => {
                // handle error case using the CurrentConsensus method
                self.current.process(peer, Err(e))
            }
        }
    }
}

/// Returns when `required` responses are equal
pub struct CurrentConsensus<R> {
    /// Previously received responses/errors
    responses: BTreeMap<PeerId, R>,
    errors: BTreeMap<PeerId, MemberError>,
    responded_peers: BTreeSet<PeerId>,
    threshold: usize,
    max_evil: usize,
}

impl<R> CurrentConsensus<R> {
    pub fn new(total_peers: usize) -> Self {
        let max_evil = (total_peers - 1) / 3;
        let threshold = total_peers - max_evil;

        Self {
            responses: BTreeMap::new(),
            errors: BTreeMap::new(),
            responded_peers: BTreeSet::new(),
            threshold,
            max_evil,
        }
    }

    pub fn full_participation(total_peers: usize) -> Self {
        Self {
            responses: BTreeMap::new(),
            errors: BTreeMap::new(),
            responded_peers: BTreeSet::new(),
            threshold: total_peers,
            max_evil: 0,
        }
    }
}

impl<R: Eq + Clone + Debug> QueryStrategy<R> for CurrentConsensus<R> {
    fn process(&mut self, peer: PeerId, result: api::MemberResult<R>) -> QueryStep<R> {
        match result {
            Ok(response) => {
                self.responses.insert(peer, response);
                self.responded_peers.insert(peer);
            }
            Err(error) => {
                self.errors.insert(peer, error);

                if self.errors.len() > self.max_evil {
                    return QueryStep::Failure {
                        general: None,
                        members: mem::take(&mut self.errors),
                    };
                }
            }
        }

        if let Some(response) = self
            .responses
            .values()
            .max_by_key(|response| self.responses.values().filter(|r| r == response).count())
        {
            let count = self.responses.values().filter(|r| r == &response).count();

            if count >= self.threshold {
                return QueryStep::Success(response.clone());
            }
        }

        if self.responded_peers.len() >= self.threshold {
            QueryStep::RetryMembers(mem::take(&mut self.responded_peers))
        } else {
            QueryStep::Continue
        }
    }
}

/// Query strategy that returns when all peers responded or a deadline passed
pub struct AllOrDeadline<R> {
    deadline: SystemTime,
    num_peers: usize,
    responses: BTreeMap<PeerId, R>,
}

impl<R> AllOrDeadline<R> {
    pub fn new(num_peers: usize, deadline: SystemTime) -> Self {
        Self {
            deadline,
            num_peers,
            responses: BTreeMap::default(),
        }
    }
}

impl<R> QueryStrategy<R, BTreeMap<PeerId, R>> for AllOrDeadline<R> {
    fn process(
        &mut self,
        peer_id: PeerId,
        response: api::MemberResult<R>,
    ) -> QueryStep<BTreeMap<PeerId, R>> {
        assert!(!self.responses.contains_key(&peer_id));
        let step = match response {
            Ok(o) => {
                self.responses.insert(peer_id, o);

                if self.responses.len() == self.num_peers {
                    return QueryStep::Success(mem::take(&mut self.responses));
                }
                QueryStep::Continue
            }
            // we rely on retries and timeouts to detect a deadline passing
            Err(_e) => QueryStep::RetryMembers(BTreeSet::from([peer_id])),
        };

        if self.deadline <= now() {
            return QueryStep::Success(mem::take(&mut self.responses));
        }

        step
    }
}

/// Query for supported api versions from all the guardians (with a deadline)
/// and calculate the best versions to use for each component (core + modules).
pub struct DiscoverApiVersionSet {
    inner: AllOrDeadline<SupportedApiVersionsSummary>,
    client_versions: SupportedApiVersionsSummary,
}

impl DiscoverApiVersionSet {
    pub fn new(
        num_peers: usize,
        deadline: SystemTime,
        client_versions: SupportedApiVersionsSummary,
    ) -> Self {
        Self {
            inner: AllOrDeadline::new(num_peers, deadline),
            client_versions,
        }
    }
}

fn discover_common_core_api_version(
    client_versions: &SupportedCoreApiVersions,
    peer_versions: BTreeMap<PeerId, SupportedCoreApiVersions>,
) -> Option<ApiVersion> {
    let mut best_major = None;
    let mut best_major_peer_num = 0;

    for client_api_version in &client_versions.api {
        let peers_compatible_num = peer_versions
            .values()
            .filter(|supported_versions| {
                (supported_versions.core_consensus == client_versions.core_consensus)
                    .then(|| {
                        supported_versions
                            .api
                            .get_by_major(client_api_version.major)
                    })
                    .flatten()
                    .map(|peer_version| client_api_version.minor <= peer_version.minor)
                    .unwrap_or(false)
            })
            .count();

        if best_major_peer_num < peers_compatible_num {
            best_major = Some(client_api_version);
            best_major_peer_num = peers_compatible_num;
        }
    }

    best_major
}

#[test]
fn discover_common_core_api_version_sanity() {
    use fedimint_core::module::MultiApiVersion;

    let core_consensus = 0.into();
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
                PeerId(0),
                SupportedCoreApiVersions {
                    core_consensus: 0.into(),
                    api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 4 }])
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
                PeerId(0),
                SupportedCoreApiVersions {
                    core_consensus: 1.into(), // wrong consensus version
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
                    PeerId(0),
                    SupportedCoreApiVersions {
                        core_consensus,
                        api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 2 }])
                            .unwrap(),
                    }
                ),
                (
                    PeerId(1),
                    SupportedCoreApiVersions {
                        core_consensus,
                        api: MultiApiVersion::try_from_iter([ApiVersion { major: 2, minor: 1 }])
                            .unwrap(),
                    }
                ),
                (
                    PeerId(1),
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
}

fn discover_common_module_api_version(
    client_versions: &SupportedModuleApiVersions,
    peer_versions: BTreeMap<PeerId, SupportedModuleApiVersions>,
) -> Option<ApiVersion> {
    let mut best_major = None;
    let mut best_major_peer_num = 0;

    for client_api_version in &client_versions.api {
        let peers_compatible_num = peer_versions
            .values()
            .filter(|supported_versions| {
                (supported_versions.core_consensus == client_versions.core_consensus
                    && supported_versions.module_consensus == client_versions.module_consensus)
                    .then(|| {
                        supported_versions
                            .api
                            .get_by_major(client_api_version.major)
                    })
                    .flatten()
                    .map(|peer_version| client_api_version.minor <= peer_version.minor)
                    .unwrap_or(false)
            })
            .count();

        if best_major_peer_num < peers_compatible_num {
            best_major = Some(client_api_version);
            best_major_peer_num = peers_compatible_num;
        }
    }

    best_major
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
        result: api::MemberResult<SupportedApiVersionsSummary>,
    ) -> QueryStep<ApiVersionSet> {
        match self.inner.process(peer, result) {
            QueryStep::Success(o) => {
                match discover_common_api_versions_set(&self.client_versions, o) {
                    Ok(o) => QueryStep::Success(o),
                    Err(e) => QueryStep::Failure {
                        general: Some(e),
                        members: BTreeMap::new(),
                    },
                }
            }
            QueryStep::RetryMembers(v) => QueryStep::RetryMembers(v),
            QueryStep::FailMembers(v) => QueryStep::FailMembers(v),
            QueryStep::Continue => QueryStep::Continue,
            QueryStep::Failure { general, members } => QueryStep::Failure { general, members },
        }
    }
}

pub trait QueryStrategy<IR, OR = IR> {
    /// Should requests for this strategy have specific timeouts?
    fn request_timeout(&self) -> Option<Duration> {
        None
    }
    fn process(&mut self, peer_id: PeerId, response: api::MemberResult<IR>) -> QueryStep<OR>;
}

/// Results from the strategy handling a response from a peer
///
/// Note that the implementation driving the [`QueryStrategy`] returning
/// [`QueryStep`] is responsible from remembering and collecting errors
/// for each peer.
#[derive(Debug)]
pub enum QueryStep<R> {
    /// Retry request to this peer
    RetryMembers(BTreeSet<PeerId>),
    /// Fail these members and remember their errors
    FailMembers(BTreeMap<PeerId, MemberError>),
    /// Do nothing yet, keep waiting for requests
    Continue,
    /// Return the successful result
    Success(R),
    /// Fail the whole request and remember errors from given members
    /// Note: member errors are to be added to any errors previously returned
    /// with `FailMembers`
    Failure {
        general: Option<anyhow::Error>,
        members: BTreeMap<PeerId, MemberError>,
    },
}

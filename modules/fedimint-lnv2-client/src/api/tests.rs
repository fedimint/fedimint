use std::collections::{BTreeMap, BTreeSet};

use fedimint_api_client::api::{DynModuleApi, IModuleFederationApi, IRawFederationApi};
use fedimint_connectors::error::ServerError;
use fedimint_connectors::{DynGuaridianConnection, PeerStatus, ServerResult};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::runtime::{Duration, Instant, sleep};
use fedimint_core::util::SafeUrl;
use fedimint_core::{PeerId, apply, async_trait_maybe_send};
use fedimint_lnv2_common::endpoint_constants::GATEWAYS_ENDPOINT;
use futures::stream::BoxStream;

use super::{GATEWAYS_GRACE_PERIOD, LightningFederationApi};

/// How a mocked guardian responds to the gateways request.
#[derive(Debug, Clone)]
enum Guardian {
    /// Answers with its gateway list after the delay.
    Answers(Duration, Vec<SafeUrl>),
    /// Fails after the delay.
    Fails(Duration),
    /// Never answers.
    Hangs,
}

#[derive(Debug)]
struct MockApi {
    peers: BTreeSet<PeerId>,
    guardians: BTreeMap<PeerId, Guardian>,
}

impl MockApi {
    fn new(guardians: impl IntoIterator<Item = Guardian>) -> Self {
        let guardians = guardians
            .into_iter()
            .zip(0..)
            .map(|(guardian, peer)| (PeerId::from(peer), guardian))
            .collect::<BTreeMap<_, _>>();

        Self {
            peers: guardians.keys().copied().collect(),
            guardians,
        }
    }
}

#[apply(async_trait_maybe_send!)]
impl IRawFederationApi for MockApi {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.peers
    }

    fn self_peer(&self) -> Option<PeerId> {
        None
    }

    fn with_module(&self, _id: ModuleInstanceId) -> DynModuleApi {
        unimplemented!()
    }

    async fn request_raw(
        &self,
        peer_id: PeerId,
        method: &str,
        _params: &ApiRequestErased,
    ) -> ServerResult<serde_json::Value> {
        assert_eq!(method, GATEWAYS_ENDPOINT);

        match self.guardians[&peer_id].clone() {
            Guardian::Answers(delay, gateways) => {
                sleep(delay).await;

                Ok(serde_json::to_value(gateways).expect("Serializes"))
            }
            Guardian::Fails(delay) => {
                sleep(delay).await;

                Err(ServerError::Connection("connection lost".into()))
            }
            Guardian::Hangs => std::future::pending().await,
        }
    }

    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, PeerStatus>> {
        unimplemented!()
    }

    async fn wait_for_initialized_connections(&self) {}

    async fn get_peer_connection(&self, _peer_id: PeerId) -> ServerResult<DynGuaridianConnection> {
        unimplemented!()
    }
}

impl IModuleFederationApi for MockApi {}

fn gateway(name: &str) -> SafeUrl {
    format!("https://{name}.example")
        .parse()
        .expect("Valid url")
}

fn secs(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

#[tokio::test(start_paused = true)]
async fn gateways_tolerate_more_than_f_failed_guardians() {
    // Of ten guardians (f = 3) two are offline and two more fail transiently,
    // which is f + 1 failures. Six guardians still list the gateway.
    let guardians = [
        vec![Guardian::Fails(secs(0)); 2],
        vec![Guardian::Fails(secs(1)); 2],
        vec![Guardian::Answers(secs(2), vec![gateway("gateway")]); 6],
    ]
    .concat();

    let gateways = MockApi::new(guardians)
        .gateways()
        .await
        .expect("Six guardians listed the gateway");

    assert_eq!(gateways, vec![gateway("gateway")]);
}

#[tokio::test(start_paused = true)]
async fn gateways_wait_for_slow_guardians_before_the_first_answer() {
    // No timer runs before the first answer, however long it takes.
    let start = Instant::now();

    let gateways = MockApi::new(vec![
        Guardian::Answers(secs(60), vec![gateway("gateway")]);
        4
    ])
    .gateways()
    .await
    .expect("All guardians answered");

    assert_eq!(gateways, vec![gateway("gateway")]);
    assert_eq!(start.elapsed(), secs(60));
}

#[tokio::test(start_paused = true)]
async fn gateways_rank_the_majority_gateway_above_a_fast_single_guardian() {
    // One guardian answers immediately with a gateway only it lists; the
    // other guardians answer within the grace period.
    let guardians = [
        vec![Guardian::Answers(secs(0), vec![gateway("single")])],
        vec![Guardian::Answers(secs(1), vec![gateway("majority")]); 3],
    ]
    .concat();

    let gateways = MockApi::new(guardians)
        .gateways()
        .await
        .expect("All guardians answered");

    assert_eq!(gateways, vec![gateway("majority"), gateway("single")]);
}

#[tokio::test(start_paused = true)]
async fn gateways_return_what_arrived_within_the_grace_period() {
    // Ten guardians need seven answers. The grace period runs from the first
    // answer and is not extended by later ones, so the answer arriving after
    // it is not waited for, and neither are the guardians that never answer.
    assert!(secs(4) < GATEWAYS_GRACE_PERIOD && GATEWAYS_GRACE_PERIOD < secs(8));

    let guardians = [
        vec![
            Guardian::Answers(secs(0), vec![gateway("first")]),
            Guardian::Answers(secs(4), vec![gateway("second")]),
            Guardian::Answers(secs(8), vec![gateway("late")]),
        ],
        vec![Guardian::Hangs; 7],
    ]
    .concat();

    let start = Instant::now();

    let mut gateways = MockApi::new(guardians)
        .gateways()
        .await
        .expect("Two guardians answered");

    gateways.sort();

    assert_eq!(gateways, vec![gateway("first"), gateway("second")]);
    assert_eq!(start.elapsed(), GATEWAYS_GRACE_PERIOD);
}

#[tokio::test(start_paused = true)]
async fn gateways_fail_once_every_guardian_failed() {
    let error = MockApi::new(vec![Guardian::Fails(secs(1)); 10])
        .gateways()
        .await
        .expect_err("No guardian answered");

    assert_eq!(error.get_peer_errors().count(), 10);
}

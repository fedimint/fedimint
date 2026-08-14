use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use fedimint_connectors::{Connectivity, PeerStatus};
use fedimint_core::PeerId;
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_dummy_client::DummyClientInit;
use fedimint_dummy_server::DummyInit;
use fedimint_gateway_common::{
    FederationConnectivity, FederationStatus, FederationStatusResponse, LightningModuleStatus,
    Lnv1RegistrationStatus, Lnv2RegistrationStatus, RegisteredProtocol, RegistrationAttempt,
    RegistrationAttemptResult, RegistrationEndpointStatus,
};
use fedimint_ln_client::{LightningClientInit, MockGatewayConnection};
use fedimint_ln_server::LightningInit;
use fedimint_testing::fixtures::Fixtures;
use fedimint_unknown_server::UnknownInit;

use super::{FederationStatusSnapshot, LightningModuleSnapshot, federation_connectivity};

fn peer_statuses(connected: usize) -> BTreeMap<PeerId, PeerStatus> {
    (0_u16..4)
        .map(|peer| {
            let status = if usize::from(peer) < connected {
                PeerStatus::Connected(Connectivity::Direct)
            } else {
                PeerStatus::Disconnected
            };
            (PeerId::from(peer), status)
        })
        .collect()
}

#[test]
fn connectivity_reports_disconnected_degraded_and_threshold() {
    assert_eq!(
        federation_connectivity(&BTreeMap::new()),
        FederationConnectivity::Disconnected
    );
    assert_eq!(
        federation_connectivity(&peer_statuses(0)),
        FederationConnectivity::Disconnected
    );
    assert_eq!(
        federation_connectivity(&peer_statuses(2)),
        FederationConnectivity::Degraded
    );
    assert_eq!(
        federation_connectivity(&peer_statuses(3)),
        FederationConnectivity::Connected
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn served_handler_returns_complete_scoped_snapshot() {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit)
        .with_server_only_module(UnknownInit)
        .with_module(
            LightningClientInit {
                gateway_conn: Some(Arc::new(MockGatewayConnection)),
            },
            LightningInit,
        )
        .with_module(
            fedimint_lnv2_client::LightningClientInit::default(),
            fedimint_lnv2_server::LightningInit,
        );
    let federation = fixtures.new_fed_degraded().await;
    let gateway = fixtures.new_gateway().await;
    federation.connect_gateway(&gateway).await;

    let response = gateway
        .handle_federation_status(federation.id())
        .await
        .expect("valid gateway status");
    assert_eq!(response.federation_id(), federation.id());
    let FederationStatus::Served {
        connectivity,
        lnv1,
        lnv2,
    } = response.status()
    else {
        panic!("served federation returned {response:#?}");
    };
    assert_eq!(*connectivity, FederationConnectivity::Connected);
    let LightningModuleStatus::Supported {
        consensus_version,
        registration:
            Lnv1RegistrationStatus::GatewayManaged {
                configured,
                endpoints,
            },
    } = lnv1
    else {
        panic!("unexpected LNv1 status in {response:#?}");
    };
    assert_eq!(*consensus_version, ModuleConsensusVersion::new(2, 1));
    assert!(*configured);
    assert_eq!(endpoints.len(), 1);
    assert!(matches!(
        endpoints.get(&RegisteredProtocol::Http),
        Some(RegistrationEndpointStatus {
            last_attempt: Some(RegistrationAttempt {
                result: RegistrationAttemptResult::Succeeded,
                ..
            }),
            advertised_ttl_remaining_secs: Some(0..=600),
        })
    ));
    assert!(
        matches!(
            lnv2,
            LightningModuleStatus::Supported {
                consensus_version,
                registration: Lnv2RegistrationStatus::FederationManaged,
            } if *consensus_version == ModuleConsensusVersion::new(1, 0)
        ),
        "{response:#?}"
    );
}

#[test]
fn snapshot_uses_exact_operational_module_and_gateway_registration() {
    let federation_id = FederationId::dummy();
    let first_id = ModuleInstanceId::from(1_u16);
    let operational_id = ModuleInstanceId::from(2_u16);
    let first_version = ModuleConsensusVersion::new(1, 0);
    let operational_version = ModuleConsensusVersion::new(2, 1);
    let endpoints = BTreeMap::from([(
        RegisteredProtocol::Http,
        RegistrationEndpointStatus {
            last_attempt: None,
            advertised_ttl_remaining_secs: None,
        },
    )]);

    let response = FederationStatusSnapshot {
        federation_id,
        connectivity: FederationConnectivity::Connected,
        lnv1: LightningModuleSnapshot {
            configured: vec![
                (first_id, first_version),
                (operational_id, operational_version),
            ],
            initialized: BTreeSet::from([first_id, operational_id]),
            operational: Some(operational_id),
            registration: Lnv1RegistrationStatus::GatewayManaged {
                configured: true,
                endpoints: endpoints.clone(),
            },
        },
        lnv2: LightningModuleSnapshot {
            configured: Vec::new(),
            initialized: BTreeSet::new(),
            operational: None,
            registration: Lnv2RegistrationStatus::FederationManaged,
        },
    }
    .into_response()
    .expect("coherent snapshot");

    assert_eq!(
        response,
        FederationStatusResponse::served(
            federation_id,
            FederationConnectivity::Connected,
            LightningModuleStatus::Supported {
                consensus_version: operational_version,
                registration: Lnv1RegistrationStatus::GatewayManaged {
                    configured: true,
                    endpoints,
                },
            },
            LightningModuleStatus::Absent {},
        )
    );
}

#[test]
fn configured_but_uninitialized_module_is_an_invariant_error() {
    let federation_id = FederationId::dummy();
    let lnv1_id = ModuleInstanceId::from(1_u16);
    let uninitialized_lnv1_id = ModuleInstanceId::from(3_u16);
    let lnv2_id = ModuleInstanceId::from(2_u16);
    let lnv1_version = ModuleConsensusVersion::new(2, 1);
    let lnv2_version = ModuleConsensusVersion::new(0, 0);

    let err = FederationStatusSnapshot {
        federation_id,
        connectivity: FederationConnectivity::Degraded,
        lnv1: LightningModuleSnapshot {
            configured: vec![
                (lnv1_id, lnv1_version),
                (uninitialized_lnv1_id, lnv1_version),
            ],
            initialized: BTreeSet::from([lnv1_id]),
            operational: Some(lnv1_id),
            registration: Lnv1RegistrationStatus::GatewayManaged {
                configured: false,
                endpoints: BTreeMap::new(),
            },
        },
        lnv2: LightningModuleSnapshot {
            configured: vec![(lnv2_id, lnv2_version)],
            initialized: BTreeSet::from([lnv2_id]),
            operational: Some(lnv2_id),
            registration: Lnv2RegistrationStatus::FederationManaged,
        },
    }
    .into_response()
    .expect_err("configured modules must initialize");

    assert!(
        err.to_string().contains("LNv1 status invariant failed"),
        "{err:#}"
    );
    assert_eq!(
        FederationStatusResponse::unserved(federation_id).status(),
        &FederationStatus::Unserved
    );
}

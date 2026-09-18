use std::collections::BTreeMap;

use fedimint_core::config::FederationId;
use fedimint_core::module::ModuleConsensusVersion;
use serde_json::json;

use super::{
    FederationConnectivity, FederationStatusResponse, LightningModuleStatus,
    Lnv1RegistrationStatus, Lnv2RegistrationStatus, RegisteredProtocol, RegistrationAttempt,
    RegistrationAttemptResult, RegistrationEndpointStatus,
};

#[test]
fn wire_shape_is_explicit_and_detail_free() {
    let federation_id = FederationId::dummy();
    let response = FederationStatusResponse::served(
        federation_id,
        FederationConnectivity::Connected,
        LightningModuleStatus::Supported {
            consensus_version: ModuleConsensusVersion::new(2, 1),
            registration: Lnv1RegistrationStatus::GatewayManaged {
                configured: true,
                endpoints: BTreeMap::from([(
                    RegisteredProtocol::Http,
                    RegistrationEndpointStatus {
                        last_attempt: Some(RegistrationAttempt {
                            completed_at_unix_secs: 100,
                            result: RegistrationAttemptResult::Failed,
                        }),
                        advertised_ttl_remaining_secs: Some(500),
                    },
                )]),
            },
        },
        LightningModuleStatus::Supported {
            consensus_version: ModuleConsensusVersion::new(0, 0),
            registration: Lnv2RegistrationStatus::FederationManaged,
        },
    );

    assert_eq!(
        serde_json::to_value(response).expect("status serializes"),
        json!({
            "federation_id": federation_id,
            "federation_status": "served",
            "connectivity": "connected",
            "lnv1": {
                "module_status": "supported",
                "consensus_version": {"major": 2, "minor": 1},
                "registration": {
                    "mode": "gateway_managed",
                    "configured": true,
                    "endpoints": {
                        "http": {
                            "last_attempt": {
                                "completed_at_unix_secs": 100,
                                "result": "failed"
                            },
                            "advertised_ttl_remaining_secs": 500
                        }
                    }
                }
            },
            "lnv2": {
                "module_status": "supported",
                "consensus_version": {"major": 0, "minor": 0},
                "registration": {"mode": "federation_managed"}
            }
        })
    );
}

#[test]
fn unserved_response_contains_no_inventory_or_module_claims() {
    let response = FederationStatusResponse::unserved(FederationId::dummy());
    let json = serde_json::to_string(&response).expect("status serializes");

    for forbidden in [
        "peer",
        "guardian",
        "route_hint",
        "balance",
        "gateway_id",
        "public_key",
        "endpoint_url",
        "error",
        "connectivity",
        "lnv1",
        "lnv2",
    ] {
        assert!(!json.contains(forbidden), "{forbidden} leaked in {json}");
    }
}

#[test]
fn response_type_rejects_invalid_generation_pairings() {
    let federation_id = FederationId::dummy();
    let response = json!({
        "federation_id": federation_id,
        "federation_status": "served",
        "connectivity": "connected",
            "lnv1": {
                "module_status": "supported",
                "consensus_version": {"major": 2, "minor": 1},
                "registration": {"mode": "federation_managed"}
        },
        "lnv2": {"module_status": "absent"}
    });
    assert!(
        serde_json::from_value::<FederationStatusResponse>(response).is_err(),
        "invalid response decoded"
    );
}

#[test]
fn response_type_rejects_claims_on_unserved_federations() {
    let response = json!({
        "federation_id": FederationId::dummy(),
        "federation_status": "unserved",
        "connectivity": "connected",
        "lnv1": {"module_status": "absent"},
        "lnv2": {"module_status": "absent"}
    });

    assert!(
        serde_json::from_value::<FederationStatusResponse>(response).is_err(),
        "contradictory unserved response decoded"
    );
}

#[test]
fn response_type_rejects_claims_on_absent_modules() {
    let response = json!({
        "federation_id": FederationId::dummy(),
        "federation_status": "served",
        "connectivity": "connected",
        "lnv1": {
            "module_status": "absent",
            "consensus_version": {"major": 2, "minor": 1}
        },
        "lnv2": {"module_status": "absent"}
    });

    assert!(
        serde_json::from_value::<FederationStatusResponse>(response).is_err(),
        "contradictory absent module decoded"
    );
}

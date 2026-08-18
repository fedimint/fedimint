use fedimint_connectors::ConnectorRegistry;
use fedimint_connectors::error::{GatewayStatusCode, ServerError};
use fedimint_core::config::FederationId;
use fedimint_core::util::SafeUrl;
use fedimint_gateway_common::{
    FederationConnectivity, FederationStatusResponse, GatewayHealth, GatewayProbeHealth,
    LightningModuleStatus, Lnv2RegistrationStatus,
};
use fedimint_ln_common::client::GatewayApi;
use fedimint_ln_common::gateway_registry::{
    Lnv1RegistryEvidenceCompatibility, Lnv1RegistryEvidenceV1,
};
use fedimint_ln_common::{LightningGateway, LightningGatewayAnnouncement};
use fedimint_lnv2_common::gateway_registry::{
    Lnv2RegistryEvidenceCompatibility, Lnv2RegistryEvidenceV1,
};
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::{
    ConfiguredModule, aggregate_complete_probes, aggregate_lnv1_evidence,
    aggregate_lnv1_gateway_health, aggregate_lnv2_evidence, aggregate_lnv2_gateway_health,
    get_federation_status, get_lnv1_gateway_probe_health, probe_all_registered,
    sanitized_probe_result, validate_federation_status,
};

fn current_response() -> FederationStatusResponse {
    FederationStatusResponse::unserved(FederationId::dummy())
}

#[test]
fn probe_transport_and_status_errors_stay_sanitized() {
    for error in [
        ServerError::Connection(anyhow::anyhow!("secret URL")),
        ServerError::Transport(anyhow::anyhow!("secret peer")),
    ] {
        assert_eq!(
            sanitized_probe_result(Err(error), |_| GatewayProbeHealth::Healthy),
            GatewayProbeHealth::Unreachable
        );
    }
    for error in [
        ServerError::InvalidResponse(anyhow::anyhow!("malformed")),
        ServerError::ServerError(anyhow::anyhow!("unknown")),
    ] {
        assert_eq!(
            sanitized_probe_result(Err(error), |_| GatewayProbeHealth::Healthy),
            GatewayProbeHealth::Indeterminate
        );
    }
    assert_eq!(
        sanitized_probe_result(
            Err(ServerError::GatewayStatus {
                status: GatewayStatusCode::NOT_FOUND,
            }),
            |_| GatewayProbeHealth::Healthy
        ),
        GatewayProbeHealth::UnknownLegacy
    );
    for status in [400, 401, 500] {
        assert_eq!(
            sanitized_probe_result(
                Err(ServerError::GatewayStatus {
                    status: GatewayStatusCode::from_u16(status).expect("valid status"),
                }),
                |_| GatewayProbeHealth::Healthy
            ),
            GatewayProbeHealth::Indeterminate,
            "status {status} must not look like a legacy gateway"
        );
    }
}

#[test]
fn complete_probe_table_never_strengthens_mixed_or_missing_evidence() {
    use GatewayProbeHealth as P;
    let cases: &[(&[P], GatewayHealth)] = &[
        (&[], GatewayHealth::Indeterminate),
        (&[P::Healthy], GatewayHealth::Healthy),
        (&[P::Healthy, P::Indeterminate], GatewayHealth::Healthy),
        (&[P::Unreachable], GatewayHealth::GatewayUnreachable),
        (
            &[P::Unreachable, P::Unreachable],
            GatewayHealth::GatewayUnreachable,
        ),
        (
            &[P::Incompatible, P::Incompatible],
            GatewayHealth::GatewayIncompatible,
        ),
        (
            &[P::UnknownLegacy, P::UnknownLegacy],
            GatewayHealth::HealthUnknownLegacy,
        ),
        (
            &[P::Unreachable, P::UnknownLegacy],
            GatewayHealth::Indeterminate,
        ),
        (
            &[P::Incompatible, P::Indeterminate],
            GatewayHealth::Indeterminate,
        ),
    ];
    for (probes, expected) in cases {
        assert_eq!(aggregate_complete_probes(probes), *expected);
    }
}

#[tokio::test]
async fn healthy_probe_wins_without_waiting_for_stalled_registration() {
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .bind()
        .await
        .expect("test connectors build");
    let client = GatewayApi::new(None, connectors);
    let stalled = SafeUrl::parse("https://stalled.example/").expect("valid URL");
    let healthy = SafeUrl::parse("https://healthy.example/").expect("valid URL");
    for registrations in [
        vec![stalled.clone(), healthy.clone()],
        vec![healthy.clone(), stalled.clone()],
    ] {
        let result = fedimint_core::task::timeout(
            std::time::Duration::from_secs(1),
            probe_all_registered(
                &client,
                FederationId::dummy(),
                registrations,
                |_, url, _| async move {
                    if url.host_str() == Some("healthy.example") {
                        GatewayProbeHealth::Healthy
                    } else {
                        std::future::pending().await
                    }
                },
            ),
        )
        .await
        .expect("healthy result must not await stalled probe");
        assert_eq!(result, GatewayHealth::Healthy);
    }
}

#[test]
fn response_cannot_escape_the_requested_federation_scope() {
    let response =
        FederationStatusResponse::unserved("01".repeat(32).parse().expect("valid federation id"));

    assert!(validate_federation_status(response, FederationId::dummy()).is_err());
}

#[tokio::test]
async fn http_client_sends_exact_public_scoped_request() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let address = listener.local_addr().expect("listener has address");
    let (request_tx, request_rx) = oneshot::channel();
    let response = serde_json::to_vec(&current_response()).expect("response serializes");
    let server = fedimint_core::runtime::spawn("gateway status client test server", async move {
        let (mut stream, _) = listener.accept().await.expect("request connects");
        let mut request = Vec::new();
        let header_end = loop {
            let mut chunk = [0; 1024];
            let read = stream.read(&mut chunk).await.expect("request is readable");
            assert_ne!(read, 0, "request ended before headers");
            request.extend_from_slice(&chunk[..read]);
            if let Some(position) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.parse::<usize>().ok())
            })
            .expect("request has content length");
        while request.len() < header_end + content_length {
            let mut chunk = [0; 1024];
            let read = stream.read(&mut chunk).await.expect("request is readable");
            assert_ne!(read, 0, "request ended before body");
            request.extend_from_slice(&chunk[..read]);
        }
        request_tx.send(request).expect("test receives request");
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    response.len()
                )
                .as_bytes(),
            )
            .await
            .expect("response headers write");
        stream
            .write_all(&response)
            .await
            .expect("response body writes");
    });
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .bind()
        .await
        .expect("test connectors build");
    let client = GatewayApi::new(None, connectors);
    let base_url = SafeUrl::parse(&format!("http://{address}/")).expect("valid test URL");

    assert_eq!(
        get_federation_status(&client, &base_url, FederationId::dummy())
            .await
            .expect("status request succeeds"),
        current_response()
    );
    let request = request_rx.await.expect("request was captured");
    let header_end = request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .expect("request has headers")
        + 4;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    assert!(headers.starts_with("POST /federation_status HTTP/1.1\r\n"));
    assert!(!headers.to_ascii_lowercase().contains("authorization:"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&request[header_end..])
            .expect("request body is JSON"),
        json!({"federation_id": FederationId::dummy()})
    );
    server.await.expect("server task completes");
}

#[tokio::test]
async fn real_http_connection_failure_is_sanitized_as_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let address = listener.local_addr().expect("listener has address");
    drop(listener);
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .bind()
        .await
        .expect("test connectors build");
    let client = GatewayApi::new(None, connectors);
    let base_url = SafeUrl::parse(&format!("http://{address}/")).expect("valid test URL");

    assert_eq!(
        get_lnv1_gateway_probe_health(&client, &base_url, FederationId::dummy()).await,
        GatewayProbeHealth::Unreachable
    );
}

#[tokio::test]
async fn lnv2_aggregation_rejects_duplicate_and_legacy_registry_evidence() {
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .bind()
        .await
        .expect("test connectors build");
    let client = GatewayApi::new(None, connectors);
    let url = SafeUrl::parse("https://gateway.example/").expect("valid test URL");

    assert_eq!(
        aggregate_lnv2_evidence(
            &client,
            FederationId::dummy(),
            Ok::<_, ()>(Lnv2RegistryEvidenceCompatibility::Compatible(
                Lnv2RegistryEvidenceV1::new(vec![url.clone(), url])
            ))
        )
        .await,
        GatewayHealth::Indeterminate
    );
    assert_eq!(
        aggregate_lnv2_evidence(
            &client,
            FederationId::dummy(),
            Ok::<_, ()>(Lnv2RegistryEvidenceCompatibility::UnknownLegacy)
        )
        .await,
        GatewayHealth::Indeterminate
    );
    assert_eq!(
        aggregate_lnv2_evidence(
            &client,
            FederationId::dummy(),
            Ok::<_, ()>(Lnv2RegistryEvidenceCompatibility::Compatible(
                Lnv2RegistryEvidenceV1::new(vec![])
            ))
        )
        .await,
        GatewayHealth::NoRegistrations
    );
}

#[tokio::test]
async fn lnv1_terminal_and_incomplete_evidence_stays_distinct() {
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .bind()
        .await
        .expect("test connectors build");
    let client = GatewayApi::new(None, connectors);
    assert_eq!(
        aggregate_lnv1_gateway_health(&client, ConfiguredModule::Absent).await,
        GatewayHealth::ModuleAbsent
    );
    assert_eq!(
        aggregate_lnv2_gateway_health(&client, ConfiguredModule::Absent).await,
        GatewayHealth::ModuleAbsent
    );
    assert_eq!(
        aggregate_lnv1_gateway_health(&client, ConfiguredModule::PresentUnusable).await,
        GatewayHealth::Indeterminate
    );
    for (evidence, expected) in [
        (
            Ok::<_, ()>(Lnv1RegistryEvidenceCompatibility::Compatible(
                Lnv1RegistryEvidenceV1::no_registrations(),
            )),
            GatewayHealth::NoRegistrations,
        ),
        (
            Ok::<_, ()>(Lnv1RegistryEvidenceCompatibility::Compatible(
                Lnv1RegistryEvidenceV1::registrations_expired(),
            )),
            GatewayHealth::RegistrationsExpired,
        ),
        (
            Ok::<_, ()>(Lnv1RegistryEvidenceCompatibility::UnknownLegacy),
            GatewayHealth::Indeterminate,
        ),
        (Err(()), GatewayHealth::Indeterminate),
    ] {
        assert_eq!(
            aggregate_lnv1_evidence(&client, FederationId::dummy(), evidence).await,
            expected
        );
    }

    let gateway_id = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        .parse()
        .expect("valid test key");
    let announcement = LightningGatewayAnnouncement {
        info: LightningGateway {
            federation_index: 0,
            gateway_redeem_key: gateway_id,
            node_pub_key: gateway_id,
            lightning_alias: "test".to_owned(),
            api: SafeUrl::parse("https://gateway.example/").expect("valid URL"),
            route_hints: vec![],
            fees: lightning_invoice::RoutingFees {
                base_msat: 0,
                proportional_millionths: 0,
            },
            gateway_id,
            supports_private_payments: false,
        },
        vetted: false,
        ttl: std::time::Duration::from_secs(60),
        auth: None,
    };
    assert_eq!(
        aggregate_lnv1_evidence(
            &client,
            FederationId::dummy(),
            Ok::<_, ()>(Lnv1RegistryEvidenceCompatibility::Compatible(
                Lnv1RegistryEvidenceV1::registrations_current(vec![
                    announcement.clone(),
                    announcement,
                ])
                .expect("nonempty")
            ))
        )
        .await,
        GatewayHealth::Indeterminate
    );
}

#[tokio::test]
async fn current_lnv2_registration_aggregates_to_healthy() {
    let federation_id = FederationId::dummy();
    let response = FederationStatusResponse::served(
        federation_id,
        FederationConnectivity::Connected,
        LightningModuleStatus::Absent {},
        LightningModuleStatus::Supported {
            consensus_version: fedimint_core::module::ModuleConsensusVersion::new(1, 0),
            registration: Lnv2RegistrationStatus::FederationManaged,
        },
    );
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let address = listener.local_addr().expect("listener has address");
    let body = serde_json::to_vec(&response).expect("response serializes");
    let server = fedimint_core::runtime::spawn("healthy gateway test server", async move {
        let (mut stream, _) = listener.accept().await.expect("request connects");
        let mut request = [0_u8; 4096];
        let _ = stream
            .read(&mut request)
            .await
            .expect("request is readable");
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .expect("headers write");
        stream.write_all(&body).await.expect("body writes");
    });
    let gateway = SafeUrl::parse(&format!("http://{address}/")).expect("valid URL");
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .bind()
        .await
        .expect("test connectors build");
    let client = GatewayApi::new(None, connectors);

    assert_eq!(
        aggregate_lnv2_evidence(
            &client,
            federation_id,
            Ok::<_, ()>(Lnv2RegistryEvidenceCompatibility::Compatible(
                Lnv2RegistryEvidenceV1::new(vec![gateway])
            ))
        )
        .await,
        GatewayHealth::Healthy
    );
    server.await.expect("server task completes");
}

use fedimint_connectors::ConnectorRegistry;
use fedimint_connectors::error::{GatewayStatusCode, ServerError};
use fedimint_core::config::FederationId;
use fedimint_core::util::SafeUrl;
use fedimint_gateway_common::{
    FederationConnectivity, FederationStatusResponse, GatewayCheckResult, GatewayHealth,
    LightningModuleStatus, Lnv2RegistrationStatus,
};
use fedimint_ln_common::client::GatewayApi;
use fedimint_ln_common::gateway_registry::{Lnv1RegistrySnapshotResult, Lnv1RegistrySnapshotV1};
use fedimint_ln_common::{LightningGateway, LightningGatewayAnnouncement};
use fedimint_lnv2_common::gateway_registry::{Lnv2RegistrySnapshotResult, Lnv2RegistrySnapshotV1};
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::{
    ConfiguredModule, check_lnv1_gateway, check_lnv1_gateways, check_lnv2_gateways,
    check_registered_gateways, classify_gateway_check, gateway_health_from_lnv1_snapshot,
    gateway_health_from_lnv2_snapshot, get_federation_status, summarize_gateway_checks,
    validate_federation_status,
};

fn current_response() -> FederationStatusResponse {
    FederationStatusResponse::unserved(FederationId::dummy())
}

#[test]
fn gateway_check_hides_transport_and_status_error_details() {
    for error in [
        ServerError::Connection(anyhow::anyhow!("secret URL")),
        ServerError::Transport(anyhow::anyhow!("secret peer")),
    ] {
        assert_eq!(
            classify_gateway_check(Err(error), |_| GatewayCheckResult::Healthy),
            GatewayCheckResult::Unreachable
        );
    }
    for error in [
        ServerError::InvalidResponse(anyhow::anyhow!("malformed")),
        ServerError::ServerError(anyhow::anyhow!("unknown")),
    ] {
        assert_eq!(
            classify_gateway_check(Err(error), |_| GatewayCheckResult::Healthy),
            GatewayCheckResult::Unknown
        );
    }
    assert_eq!(
        classify_gateway_check(
            Err(ServerError::GatewayStatus {
                status: GatewayStatusCode::NOT_FOUND,
            }),
            |_| GatewayCheckResult::Healthy
        ),
        GatewayCheckResult::EndpointUnavailable
    );
    for status in [400, 401, 500] {
        assert_eq!(
            classify_gateway_check(
                Err(ServerError::GatewayStatus {
                    status: GatewayStatusCode::from_u16(status).expect("valid status"),
                }),
                |_| GatewayCheckResult::Healthy
            ),
            GatewayCheckResult::Unknown,
            "status {status} must not look like a legacy gateway"
        );
    }
}

#[test]
fn mixed_or_missing_gateway_checks_return_unknown() {
    use GatewayCheckResult as P;
    let cases: &[(&[P], GatewayHealth)] = &[
        (&[], GatewayHealth::Unknown),
        (&[P::Healthy], GatewayHealth::Healthy),
        (&[P::Healthy, P::Unknown], GatewayHealth::Healthy),
        (&[P::Unreachable], GatewayHealth::GatewayUnreachable),
        (
            &[P::Unreachable, P::Unreachable],
            GatewayHealth::GatewayUnreachable,
        ),
        (
            &[P::EndpointUnavailable, P::EndpointUnavailable],
            GatewayHealth::GatewayStatusUnavailable,
        ),
        (
            &[P::Unreachable, P::EndpointUnavailable],
            GatewayHealth::Unknown,
        ),
        (&[P::Unreachable, P::Unknown], GatewayHealth::Unknown),
    ];
    for (checks, expected) in cases {
        assert_eq!(summarize_gateway_checks(checks), *expected);
    }
}

#[tokio::test]
async fn healthy_check_wins_without_waiting_for_stalled_registration() {
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
            check_registered_gateways(
                &client,
                FederationId::dummy(),
                registrations,
                |_, url, _| async move {
                    if url.host_str() == Some("healthy.example") {
                        GatewayCheckResult::Healthy
                    } else {
                        std::future::pending().await
                    }
                },
            ),
        )
        .await
        .expect("healthy result must not await stalled check");
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
async fn http_connection_failure_returns_unreachable() {
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
        check_lnv1_gateway(&client, &base_url, FederationId::dummy()).await,
        GatewayCheckResult::Unreachable
    );
}

#[tokio::test]
async fn lnv2_health_rejects_duplicate_urls_and_missing_snapshot_endpoint() {
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .bind()
        .await
        .expect("test connectors build");
    let client = GatewayApi::new(None, connectors);
    let url = SafeUrl::parse("https://gateway.example/").expect("valid test URL");

    assert_eq!(
        gateway_health_from_lnv2_snapshot(
            &client,
            FederationId::dummy(),
            Ok::<_, ()>(Lnv2RegistrySnapshotResult::Snapshot(
                Lnv2RegistrySnapshotV1::new(vec![url.clone(), url])
            ))
        )
        .await,
        GatewayHealth::Unknown
    );
    assert_eq!(
        gateway_health_from_lnv2_snapshot(
            &client,
            FederationId::dummy(),
            Ok::<_, ()>(Lnv2RegistrySnapshotResult::EndpointUnavailable)
        )
        .await,
        GatewayHealth::Unknown
    );
    assert_eq!(
        gateway_health_from_lnv2_snapshot(
            &client,
            FederationId::dummy(),
            Ok::<_, ()>(Lnv2RegistrySnapshotResult::Snapshot(
                Lnv2RegistrySnapshotV1::new(vec![])
            ))
        )
        .await,
        GatewayHealth::NoRegistrations
    );
}

#[tokio::test]
async fn lnv1_health_distinguishes_registry_states_and_missing_results() {
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .bind()
        .await
        .expect("test connectors build");
    let client = GatewayApi::new(None, connectors);
    assert_eq!(
        check_lnv1_gateways(&client, ConfiguredModule::Absent).await,
        GatewayHealth::ModuleAbsent
    );
    assert_eq!(
        check_lnv2_gateways(&client, ConfiguredModule::Absent).await,
        GatewayHealth::ModuleAbsent
    );
    assert_eq!(
        check_lnv1_gateways(&client, ConfiguredModule::PresentUnusable).await,
        GatewayHealth::Unknown
    );
    for (snapshot_result, expected) in [
        (
            Ok::<_, ()>(Lnv1RegistrySnapshotResult::Snapshot(
                Lnv1RegistrySnapshotV1::no_registrations(),
            )),
            GatewayHealth::NoRegistrations,
        ),
        (
            Ok::<_, ()>(Lnv1RegistrySnapshotResult::Snapshot(
                Lnv1RegistrySnapshotV1::registrations_expired(),
            )),
            GatewayHealth::RegistrationsExpired,
        ),
        (
            Ok::<_, ()>(Lnv1RegistrySnapshotResult::EndpointUnavailable),
            GatewayHealth::Unknown,
        ),
        (Err(()), GatewayHealth::Unknown),
    ] {
        assert_eq!(
            gateway_health_from_lnv1_snapshot(&client, FederationId::dummy(), snapshot_result)
                .await,
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
        gateway_health_from_lnv1_snapshot(
            &client,
            FederationId::dummy(),
            Ok::<_, ()>(Lnv1RegistrySnapshotResult::Snapshot(
                Lnv1RegistrySnapshotV1::registrations_current(vec![
                    announcement.clone(),
                    announcement,
                ])
                .expect("nonempty")
            ))
        )
        .await,
        GatewayHealth::Unknown
    );
}

#[tokio::test]
async fn current_lnv2_registration_returns_healthy() {
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
        gateway_health_from_lnv2_snapshot(
            &client,
            federation_id,
            Ok::<_, ()>(Lnv2RegistrySnapshotResult::Snapshot(
                Lnv2RegistrySnapshotV1::new(vec![gateway])
            ))
        )
        .await,
        GatewayHealth::Healthy
    );
    server.await.expect("server task completes");
}

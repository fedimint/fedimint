use std::str::FromStr as _;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::IrohGatewayRequest;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::SafeUrl;
use fedimint_gateway_common::{
    ChainSource, FederationStatusRequest, FederationStatusResponse, LightningMode,
};
use fedimint_testing_core::test_dir;
use tower::ServiceExt as _;

use super::{
    FEDERATION_STATUS_ENDPOINT, GATEWAY_INFO_ENDPOINT, LIQUIDITY_MANAGER_ROUTES, MNEMONIC_ENDPOINT,
    V1_API_ENDPOINT, is_allowed_not_configured_api, public_routes, routes, strip_v1_prefix,
};
use crate::client::GatewayClientBuilder;
use crate::config::DatabaseBackend;
use crate::iroh_server::{Handlers, handle_request};
use crate::{Gateway, GatewayState};

#[test]
fn strip_v1_prefix_covers_both_api_mounts() {
    for route in LIQUIDITY_MANAGER_ROUTES {
        assert_eq!(strip_v1_prefix(route), route);
        assert_eq!(
            strip_v1_prefix(&format!("/{V1_API_ENDPOINT}{route}")),
            route
        );
    }
}

#[test]
fn strip_v1_prefix_only_strips_a_full_leading_segment() {
    assert_eq!(strip_v1_prefix("/v1"), "/v1");
    assert_eq!(strip_v1_prefix("/v1x/address"), "/v1x/address");
    assert_eq!(strip_v1_prefix("/v1/v1/address"), "/v1/address");
}

#[test]
fn unconfigured_gateway_allows_only_mnemonic_setup_on_both_mounts() {
    for route in [
        FEDERATION_STATUS_ENDPOINT.to_owned(),
        format!("/{V1_API_ENDPOINT}{FEDERATION_STATUS_ENDPOINT}"),
    ] {
        assert!(!is_allowed_not_configured_api(&Method::POST, &route));
    }
    for route in [
        MNEMONIC_ENDPOINT.to_owned(),
        format!("/{V1_API_ENDPOINT}{MNEMONIC_ENDPOINT}"),
    ] {
        assert!(is_allowed_not_configured_api(&Method::POST, &route));
        assert!(!is_allowed_not_configured_api(&Method::GET, &route));
    }
}

#[test]
fn unconfigured_gateway_does_not_make_global_info_public() {
    assert!(!is_allowed_not_configured_api(
        &Method::GET,
        GATEWAY_INFO_ENDPOINT
    ));
    assert!(is_allowed_not_configured_api(
        &Method::POST,
        MNEMONIC_ENDPOINT
    ));
}

#[test]
fn federation_status_is_public_for_http_and_iroh() {
    let mut handlers = Handlers::new();
    let _http_routes = public_routes(&mut handlers);

    assert!(!handlers.is_authenticated(FEDERATION_STATUS_ENDPOINT));
}

struct TestGateway {
    /// Gateway under test.
    gateway: std::sync::Arc<Gateway>,
    /// Owns the RocksDB directory for the gateway's full lifetime.
    _guard: Option<tempfile::TempDir>,
}

async fn test_gateway(state: GatewayState) -> TestGateway {
    let gateway_db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
    let (path, guard) = test_dir(&format!("gateway-status-{}", rand::random::<u64>()));
    let client_builder = GatewayClientBuilder::new(
        path,
        ClientModuleInitRegistry::default(),
        DatabaseBackend::RocksDb,
    )
    .await
    .expect("gateway client builder initializes");
    let gateway = Gateway::builder(
        LightningMode::Lnd {
            lnd_rpc_addr: "unused".to_owned(),
            lnd_tls_cert: "unused".to_owned(),
            lnd_macaroon: "unused".to_owned(),
            lnd_time_pref: 0.5,
            lnd_payment_timeout_secs: 30,
        },
        client_builder,
        gateway_db,
    )
    .bcrypt_password_hash(
        bcrypt::HashParts::from_str(
            &bcrypt::hash("password", bcrypt::DEFAULT_COST).expect("password hashes"),
        )
        .expect("hash parses"),
    )
    .gateway_state(state)
    .chain_source(ChainSource::Esplora {
        server_url: SafeUrl::parse("http://127.0.0.1:1").expect("valid URL"),
    })
    .build()
    .await
    .expect("gateway builds");
    TestGateway {
        gateway: std::sync::Arc::new(gateway),
        _guard: guard,
    }
}

fn status_request() -> Request<Body> {
    Request::post(FEDERATION_STATUS_ENDPOINT)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&FederationStatusRequest {
                federation_id: fedimint_core::config::FederationId::dummy(),
            })
            .expect("request serializes"),
        ))
        .expect("valid request")
}

#[tokio::test]
async fn http_and_iroh_dispatch_status_publicly_but_protect_global_info() {
    let gateway_fixture = test_gateway(GatewayState::Disconnected).await;
    let gateway = gateway_fixture.gateway.clone();
    let mut handlers = Handlers::new();
    let router = routes(gateway.clone(), TaskGroup::new(), &mut handlers);
    let handlers = std::sync::Arc::new(handlers);

    let response = router
        .clone()
        .oneshot(status_request())
        .await
        .expect("HTTP dispatch succeeds");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("HTTP body reads");
    let status: FederationStatusResponse =
        serde_json::from_slice(&body).expect("HTTP status decodes");
    assert_eq!(
        status,
        FederationStatusResponse::unserved(fedimint_core::config::FederationId::dummy())
    );

    let response = router
        .clone()
        .oneshot(
            Request::get(GATEWAY_INFO_ENDPOINT)
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("HTTP dispatch succeeds");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let (status_code, body) = handle_request(
        &IrohGatewayRequest {
            route: FEDERATION_STATUS_ENDPOINT.to_owned(),
            params: Some(
                serde_json::to_value(FederationStatusRequest {
                    federation_id: fedimint_core::config::FederationId::dummy(),
                })
                .expect("request serializes"),
            ),
            password: None,
        },
        gateway.clone(),
        handlers.clone(),
        TaskGroup::new(),
    )
    .await
    .expect("Iroh dispatch succeeds");
    assert_eq!(status_code, StatusCode::OK);
    let status: FederationStatusResponse =
        serde_json::from_value(body.0).expect("Iroh status decodes");
    assert_eq!(
        status,
        FederationStatusResponse::unserved(fedimint_core::config::FederationId::dummy())
    );

    let (status_code, _) = handle_request(
        &IrohGatewayRequest {
            route: GATEWAY_INFO_ENDPOINT.to_owned(),
            params: None,
            password: None,
        },
        gateway.clone(),
        handlers,
        TaskGroup::new(),
    )
    .await
    .expect("Iroh dispatch succeeds");
    assert_eq!(status_code, StatusCode::UNAUTHORIZED);

    let (mnemonic_sender, _) = tokio::sync::broadcast::channel(1);
    let unconfigured_fixture = test_gateway(GatewayState::NotConfigured { mnemonic_sender }).await;
    let unconfigured_gateway = unconfigured_fixture.gateway.clone();
    let mut unconfigured_handlers = Handlers::new();
    let unconfigured_router = routes(
        unconfigured_gateway,
        TaskGroup::new(),
        &mut unconfigured_handlers,
    );
    let response = unconfigured_router
        .clone()
        .oneshot(status_request())
        .await
        .expect("HTTP dispatch succeeds");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = unconfigured_router
        .clone()
        .oneshot(
            Request::get(GATEWAY_INFO_ENDPOINT)
                .body(Body::empty())
                .expect("valid request"),
        )
        .await
        .expect("HTTP dispatch succeeds");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let (status_code, _) = handle_request(
        &IrohGatewayRequest {
            route: FEDERATION_STATUS_ENDPOINT.to_owned(),
            params: Some(
                serde_json::to_value(FederationStatusRequest {
                    federation_id: fedimint_core::config::FederationId::dummy(),
                })
                .expect("request serializes"),
            ),
            password: None,
        },
        unconfigured_fixture.gateway,
        std::sync::Arc::new(unconfigured_handlers),
        TaskGroup::new(),
    )
    .await
    .expect("Iroh dispatch succeeds");
    assert_eq!(status_code, StatusCode::NOT_FOUND);
}

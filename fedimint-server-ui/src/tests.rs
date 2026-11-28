use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::response::Response;
use fedimint_core::PeerId;
use fedimint_core::admin_client::GuardianConfigBackup;
use fedimint_core::core::ModuleKind;
use fedimint_core::module::ApiAuth;
use fedimint_core::module::audit::AuditSummary;
use fedimint_core::net::auth::GuardianAuthToken;
use fedimint_core::session_outcome::SessionStatusV2;
use fedimint_core::util::SafeUrl;
use fedimint_server_core::DynServerModule;
use fedimint_server_core::dashboard_ui::{
    DashboardPeerAvailability, IDashboardApi, P2PConnectionStatus, ServerBitcoinRpcStatus,
};
use fedimint_server_core::setup_ui::ISetupApi;
use fedimint_ui_common::LOGIN_ROUTE;
use tower::ServiceExt as _;

use crate::setup::{RESTORE_GUARDIAN_ROUTE, START_FEDERATION_ROUTE};
use crate::{METRICS_ROUTE, dashboard, setup};

const HOST: &str = "guardian.example:8443";
const ORIGIN: &str = "https://guardian.example:8443";
const PASSWORD: &str = "test-password";

/// Inert Guardian API for HTTP routing tests. It never writes state or restores
/// a backup.
struct TestApi {
    /// Password to use for the real UI login flow, if enabled.
    password: Option<ApiAuth>,
}

impl TestApi {
    fn new(requires_auth: bool) -> Self {
        Self {
            password: requires_auth.then(|| ApiAuth::new(PASSWORD.to_owned())),
        }
    }
}

#[async_trait]
impl ISetupApi for TestApi {
    fn auth_ui(&self) -> Option<ApiAuth> {
        self.password.clone()
    }

    async fn setup_code(&self) -> Option<String> {
        None
    }

    fn available_modules(&self) -> BTreeSet<ModuleKind> {
        BTreeSet::new()
    }

    fn default_modules(&self) -> BTreeSet<ModuleKind> {
        BTreeSet::new()
    }

    async fn set_local_parameters(
        &self,
        _name: String,
        _disable_base_fees: Option<bool>,
        _enabled_modules: Option<BTreeSet<ModuleKind>>,
        _federation_size: Option<u32>,
    ) -> Result<String> {
        Ok("mock-setup-code".to_owned())
    }

    async fn fedimintd_version(&self) -> String {
        "test-version".to_owned()
    }

    async fn fedimintd_version_hash(&self) -> Option<String> {
        None
    }

    async fn guardian_name(&self) -> Option<String> {
        unimplemented!()
    }
    async fn connected_peers(&self) -> Vec<String> {
        unimplemented!()
    }
    async fn reset_setup_codes(&self) {
        unimplemented!()
    }
    async fn add_peer_setup_code(&self, _info: String) -> Result<String> {
        unimplemented!()
    }
    async fn start_dkg(&self) -> Result<()> {
        unimplemented!()
    }
    async fn restore_from_backup(&self, _password: Option<String>, _backup: Vec<u8>) -> Result<()> {
        unimplemented!()
    }
    async fn federation_size(&self) -> Option<u32> {
        unimplemented!()
    }
    async fn cfg_federation_name(&self) -> Option<String> {
        unimplemented!()
    }
    async fn cfg_base_fees_disabled(&self) -> Option<bool> {
        unimplemented!()
    }
    async fn cfg_enabled_modules(&self) -> Option<BTreeSet<ModuleKind>> {
        unimplemented!()
    }
}

#[async_trait]
impl IDashboardApi for TestApi {
    fn auth_ui(&self) -> Option<ApiAuth> {
        self.password.clone()
    }

    fn get_module_by_kind(&self, _kind: ModuleKind) -> Option<&DynServerModule> {
        None
    }

    async fn guardian_id(&self) -> PeerId {
        unimplemented!()
    }
    async fn guardian_names(&self) -> BTreeMap<PeerId, String> {
        unimplemented!()
    }
    async fn federation_name(&self) -> Option<String> {
        unimplemented!()
    }
    async fn session_count(&self) -> u64 {
        unimplemented!()
    }
    async fn get_session_status(&self, _session_idx: u64) -> SessionStatusV2 {
        unimplemented!()
    }
    async fn consensus_ord_latency(&self) -> Option<Duration> {
        unimplemented!()
    }
    async fn p2p_connection_status(&self) -> BTreeMap<PeerId, Option<P2PConnectionStatus>> {
        unimplemented!()
    }
    async fn peer_availability(&self) -> Option<DashboardPeerAvailability> {
        unimplemented!()
    }
    async fn federation_invite_code(&self) -> String {
        unimplemented!()
    }
    async fn federation_audit(&self) -> AuditSummary {
        unimplemented!()
    }
    async fn bitcoin_rpc_url(&self) -> SafeUrl {
        unimplemented!()
    }
    async fn bitcoin_rpc_status(&self) -> Option<ServerBitcoinRpcStatus> {
        unimplemented!()
    }
    async fn download_guardian_config_backup(
        &self,
        _guardian_auth: &GuardianAuthToken,
    ) -> GuardianConfigBackup {
        unimplemented!()
    }
    async fn fedimintd_version(&self) -> String {
        unimplemented!()
    }
    async fn fedimintd_version_hash(&self) -> Option<String> {
        unimplemented!()
    }
}

async fn send(router: &Router, request: Request) -> Response {
    router.clone().oneshot(request).await.unwrap()
}

fn login_request(origin: &str) -> Request {
    Request::post(LOGIN_ROUTE)
        .header(header::HOST, HOST)
        .header(header::ORIGIN, origin)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("password={PASSWORD}")))
        .unwrap()
}

async fn login(router: &Router) -> String {
    let response = send(router, login_request(ORIGIN)).await;
    assert_eq!(response.status(), StatusCode::OK);
    response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn setup_authenticates_before_multipart_extraction() {
    let router = setup::router(ISetupApi::into_dyn(TestApi::new(true)));

    for route in [START_FEDERATION_ROUTE, RESTORE_GUARDIAN_ROUTE] {
        let request = Request::get(route).body(Body::empty()).unwrap();
        let response = send(&router, request).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], LOGIN_ROUTE);
    }

    let request = || {
        // An empty request without a multipart boundary fails extraction if it
        // gets past the session check; there is no backup payload.
        Request::post(RESTORE_GUARDIAN_ROUTE)
            .header(header::HOST, HOST)
            .header(header::ORIGIN, ORIGIN)
    };
    let response = send(&router, request().body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], LOGIN_ROUTE);

    let cookie = login(&router).await;
    let request = request()
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        send(&router, request).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn guardian_login_enforces_origin_and_preserves_proxy_port() {
    let setup = setup::router(ISetupApi::into_dyn(TestApi::new(true)));
    let dashboard = dashboard::router(IDashboardApi::into_dyn(TestApi::new(true)));
    for router in [setup, dashboard] {
        let response = send(&router, login_request("https://guardian.example:9443")).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!response.headers().contains_key(header::SET_COOKIE));

        // The Origin fallback compares the port sent through the proxy.
        assert!(!login(&router).await.is_empty());
    }
}

#[tokio::test]
async fn setup_checks_form_origin_with_session_or_without_password() {
    for requires_auth in [true, false] {
        let router = setup::router(ISetupApi::into_dyn(TestApi::new(requires_auth)));
        let cookie = if requires_auth {
            Some(login(&router).await)
        } else {
            None
        };
        let request = |origin: &str| {
            let mut request = Request::post("/")
                .header(header::HOST, HOST)
                .header(header::ORIGIN, origin)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            if let Some(cookie) = &cookie {
                request = request.header(header::COOKIE, cookie);
            }
            request.body(Body::from("name=Guardian")).unwrap()
        };
        let response = send(&router, request("https://other.example")).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = send(&router, request(ORIGIN)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["hx-redirect"],
            setup::FEDERATION_SETUP_ROUTE
        );
    }
}

#[tokio::test]
async fn passwordless_dashboard_keeps_login_unmounted() {
    let router = dashboard::router(IDashboardApi::into_dyn(TestApi::new(false)));
    let response = send(&router, login_request(ORIGIN)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let request = Request::get(METRICS_ROUTE).body(Body::empty()).unwrap();
    assert_eq!(send(&router, request).await.status(), StatusCode::OK);
}

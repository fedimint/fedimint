use std::pin::Pin;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use fedimint_core::module::ApiAuth;
use fedimint_core::task::TaskHandle;
use fedimint_server_core::setup_ui::DynSetupApi;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

pub const INIT_SETUP_ROUTE: &str = "/init_setup";
pub const ADD_SETUP_CODE_ROUTE: &str = "/add_setup_code";
pub const START_DKG_ROUTE: &str = "/start_dkg";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitSetupRequest {
    pub auth: ApiAuth,
    pub name: String,
    pub federation_name: Option<String>,
}

async fn init_setup(
    State(state): State<DynSetupApi>,
    Json(request): Json<InitSetupRequest>,
) -> Result<String, StatusCode> {
    state
        .init_setup(request.auth, request.name, request.federation_name)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)
}

async fn add_setup_code(
    State(state): State<DynSetupApi>,
    Json(code): Json<String>,
) -> Result<String, StatusCode> {
    state
        .add_setup_code(code)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)
}

async fn start_dkg(State(state): State<DynSetupApi>) -> Result<(), StatusCode> {
    state.start_dkg().await.map_err(|_| StatusCode::BAD_REQUEST)
}

pub fn setup_start(
    setup_api: DynSetupApi,
    ui_bind: std::net::SocketAddr,
    task_handle: TaskHandle,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    let app = Router::new()
        .route(INIT_SETUP_ROUTE, post(init_setup))
        .route(ADD_SETUP_CODE_ROUTE, post(add_setup_code))
        .route(START_DKG_ROUTE, post(start_dkg))
        .with_state(setup_api);

    Box::pin(async move {
        let listener = TcpListener::bind(ui_bind)
            .await
            .expect("Failed to bind devimint setup API");

        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(task_handle.make_shutdown_rx())
            .await
            .expect("Failed to serve devimint setup API");
    })
}

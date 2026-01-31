//! HTTP server for exposing Prometheus metrics.
//!
//! This module is conditionally compiled only for non-wasm targets because it
//! depends on `axum` and `tokio` networking features which are not available
//! in wasm environments. The core metrics functionality (registration,
//! encoding) remains available on all platforms via the parent module.

use std::net::SocketAddr;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use fedimint_core::task::TaskGroup;
use tokio::net::TcpListener;
use tracing::{info, warn};

use super::get_metrics;

async fn get_metrics_handler() -> (StatusCode, String) {
    match get_metrics() {
        Ok(result) => (StatusCode::OK, result),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")),
    }
}

/// Spawns an HTTP server that exposes Prometheus metrics on `/metrics`.
pub async fn spawn_api_server(
    bind_address: SocketAddr,
    task_group: TaskGroup,
) -> anyhow::Result<()> {
    let app = Router::new().route("/metrics", get(get_metrics_handler));
    let listener = TcpListener::bind(bind_address).await?;

    task_group.spawn_cancellable("Metrics Server", async move {
        if let Err(e) = axum::serve(listener, app.into_make_service()).await {
            warn!("Error running metrics server: {e:?}");
        }
    });

    info!(
        listen = %bind_address,
        "Started metrics server"
    );

    Ok(())
}

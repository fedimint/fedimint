use std::net::SocketAddr;

use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use fedimint_core::task::TaskGroup;
pub use lazy_static::lazy_static;
pub use prometheus::{
    self, histogram_opts, opts, register_histogram, register_int_counter, Encoder, Histogram,
    IntCounter, TextEncoder,
};
use tokio::sync::oneshot;
use tracing::error;

async fn get_metrics() -> (StatusCode, String) {
    let metric_families = prometheus::gather();
    let result = || -> anyhow::Result<String> {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    };
    match result() {
        Ok(result) => (StatusCode::OK, result),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")),
    }
}

pub async fn run_api_server(
    bind_address: &SocketAddr,
    task_group: &mut TaskGroup,
) -> anyhow::Result<oneshot::Receiver<()>> {
    let app = Router::new().route("/metrics", get(get_metrics));
    let server = axum::Server::bind(bind_address).serve(app.into_make_service());

    let handle = task_group.make_handle();
    let shutdown_rx = handle.make_shutdown_rx().await;
    task_group
        .spawn("Metrics Api", move |_| async move {
            let graceful = server.with_graceful_shutdown(async {
                shutdown_rx.await.ok();
            });

            if let Err(e) = graceful.await {
                error!("Error shutting down metrics api: {e:?}");
            }
        })
        .await;
    let shutdown_receiver = handle.make_shutdown_rx().await;

    Ok(shutdown_receiver)
}

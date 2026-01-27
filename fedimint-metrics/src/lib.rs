#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

use std::net::SocketAddr;
use std::sync::LazyLock;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use fedimint_core::task::{TaskGroup, TaskShutdownToken};
use prometheus::Registry;
pub use prometheus::{
    self, Encoder, Gauge, GaugeVec, Histogram, HistogramVec, IntCounter, IntCounterVec,
    TextEncoder, histogram_opts, opts, register_histogram_with_registry,
    register_int_counter_vec_with_registry,
};
use tokio::net::TcpListener;
use tracing::error;

pub static REGISTRY: LazyLock<Registry> =
    LazyLock::new(|| Registry::new_custom(Some("fm".into()), None).unwrap());

pub static AMOUNTS_BUCKETS_SATS: LazyLock<Vec<f64>> = LazyLock::new(|| {
    vec![
        0.0,
        0.1,
        1.0,
        10.0,
        100.0,
        1000.0,
        10000.0,
        100_000.0,
        1_000_000.0,
        10_000_000.0,
        100_000_000.0,
    ]
});

/// Returns all registered metrics encoded in Prometheus text format.
pub fn get_metrics() -> anyhow::Result<String> {
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    encoder.encode(&metric_families, &mut buffer)?;
    Ok(String::from_utf8(buffer)?)
}

async fn get_metrics_handler() -> (StatusCode, String) {
    match get_metrics() {
        Ok(result) => (StatusCode::OK, result),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")),
    }
}

pub async fn run_api_server(
    bind_address: SocketAddr,
    task_group: TaskGroup,
) -> anyhow::Result<TaskShutdownToken> {
    let app = Router::new().route("/metrics", get(get_metrics_handler));
    let listener = TcpListener::bind(bind_address).await?;
    let serve = axum::serve(listener, app.into_make_service());

    let handle = task_group.make_handle();
    let shutdown_rx = handle.make_shutdown_rx();
    task_group.spawn("Metrics Api", |_| async {
        let graceful = serve.with_graceful_shutdown(async {
            shutdown_rx.await;
        });

        if let Err(e) = graceful.await {
            error!("Error shutting down metrics api: {e:?}");
        }
    });
    let shutdown_receiver = handle.make_shutdown_rx();

    Ok(shutdown_receiver)
}

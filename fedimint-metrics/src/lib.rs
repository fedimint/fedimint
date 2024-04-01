use std::net::SocketAddr;

use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use fedimint_core::task::{TaskGroup, TaskShutdownToken};
pub use lazy_static::lazy_static;
use prometheus::Registry;
pub use prometheus::{
    self, histogram_opts, opts, register_histogram_with_registry,
    register_int_counter_vec_with_registry, Encoder, Gauge, GaugeVec, Histogram, HistogramVec,
    IntCounter, IntCounterVec, TextEncoder,
};
use tokio::net::TcpListener;
use tracing::error;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new_custom(Some("fm".into()), None).unwrap();
    pub static ref AMOUNTS_BUCKETS_SATS: Vec<f64> = vec![
        0.0,
        0.1,
        1.0,
        10.0,
        100.0,
        1000.0,
        10000.0,
        100000.0,
        1000000.0,
        10000000.0,
        100000000.0
    ];
}

async fn get_metrics() -> (StatusCode, String) {
    let metric_families = REGISTRY.gather();
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
    bind_address: SocketAddr,
    task_group: TaskGroup,
) -> anyhow::Result<TaskShutdownToken> {
    let app = Router::new().route("/metrics", get(get_metrics));
    let listener = TcpListener::bind(bind_address).await?;
    let serve = axum::serve(listener, app.into_make_service());

    let handle = task_group.make_handle();
    let shutdown_rx = handle.make_shutdown_rx().await;
    task_group.spawn("Metrics Api", move |_| async move {
        let graceful = serve.with_graceful_shutdown(async {
            shutdown_rx.await;
        });

        if let Err(e) = graceful.await {
            error!("Error shutting down metrics api: {e:?}");
        }
    });
    let shutdown_receiver = handle.make_shutdown_rx().await;

    Ok(shutdown_receiver)
}

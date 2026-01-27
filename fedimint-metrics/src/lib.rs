#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

use std::sync::LazyLock;

use prometheus::Registry;
pub use prometheus::{
    self, Encoder, Gauge, GaugeVec, Histogram, HistogramVec, IntCounter, IntCounterVec,
    TextEncoder, histogram_opts, opts, register_histogram_with_registry,
    register_int_counter_vec_with_registry,
};

// The server module depends on `axum` and `tokio` networking, which are not
// available on wasm targets. Core metrics functionality (REGISTRY, get_metrics,
// metric registration) remains available on all platforms.
#[cfg(not(target_family = "wasm"))]
mod server;
#[cfg(not(target_family = "wasm"))]
pub use server::spawn_api_server;

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

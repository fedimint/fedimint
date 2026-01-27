use std::sync::LazyLock;

use fedimint_metrics::prometheus::{
    HistogramVec, IntCounterVec, register_histogram_vec_with_registry,
};
use fedimint_metrics::{REGISTRY, histogram_opts, opts, register_int_counter_vec_with_registry};

/// Histogram of API request durations in seconds, labeled by method
pub static CLIENT_API_REQUEST_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "client_api_request_duration_seconds",
            "Duration of client API requests to federation peers",
        ),
        &["method", "peer_id"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Counter of API requests made, labeled by method and peer
pub static CLIENT_API_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "client_api_requests_total",
            "Total number of client API requests to federation peers",
        ),
        &["method", "peer_id", "result"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

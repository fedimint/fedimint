use std::sync::LazyLock;

use fedimint_metrics::prometheus::{
    HistogramVec, IntCounterVec, register_histogram_vec_with_registry,
};
use fedimint_metrics::{REGISTRY, histogram_opts, opts, register_int_counter_vec_with_registry};

/// Histogram of Lightning RPC request durations in seconds, labeled by method
/// and name
pub static LN_RPC_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "ln_rpc_request_duration_seconds",
            "Duration of Lightning RPC requests",
        ),
        &["method", "name"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Counter of Lightning RPC requests, labeled by method, name, and result
pub static LN_RPC_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "ln_rpc_requests_total",
            "Total number of Lightning RPC requests",
        ),
        &["method", "name", "result"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

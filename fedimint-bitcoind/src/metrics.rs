use std::sync::LazyLock;

use fedimint_metrics::prometheus::{
    HistogramVec, IntCounterVec, register_histogram_vec_with_registry,
};
use fedimint_metrics::{REGISTRY, histogram_opts, opts, register_int_counter_vec_with_registry};

/// Histogram of bitcoind RPC request durations in seconds, labeled by method
/// and name
pub static BITCOIND_RPC_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "bitcoind_rpc_request_duration_seconds",
            "Duration of bitcoind RPC requests",
        ),
        &["method", "name"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Counter of bitcoind RPC requests, labeled by method, name, and result
pub static BITCOIND_RPC_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "bitcoind_rpc_requests_total",
            "Total number of bitcoind RPC requests",
        ),
        &["method", "name", "result"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

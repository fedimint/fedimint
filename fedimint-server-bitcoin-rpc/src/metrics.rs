use std::sync::LazyLock;

use fedimint_metrics::prometheus::{
    HistogramVec, IntCounterVec, register_histogram_vec_with_registry,
};
use fedimint_metrics::{REGISTRY, histogram_opts, opts, register_int_counter_vec_with_registry};

/// Histogram of server bitcoind RPC request durations in seconds, labeled by
/// method
pub static SERVER_BITCOIND_RPC_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "server_bitcoind_rpc_request_duration_seconds",
            "Duration of server-side bitcoind RPC requests",
        ),
        &["method"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Counter of server bitcoind RPC requests, labeled by method and result
pub static SERVER_BITCOIND_RPC_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "server_bitcoind_rpc_requests_total",
            "Total number of server-side bitcoind RPC requests",
        ),
        &["method", "result"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

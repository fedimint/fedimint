use std::sync::LazyLock;

use fedimint_metrics::prometheus::{
    HistogramVec, IntCounterVec, register_histogram_vec_with_registry,
};
use fedimint_metrics::{REGISTRY, histogram_opts, opts, register_int_counter_vec_with_registry};

/// Histogram of connection durations in seconds, labeled by scheme
/// (ws/wss/iroh/http/https)
pub static CONNECTION_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "connector_connection_duration_seconds",
            "Duration of establishing connections to federation peers",
        ),
        &["scheme"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Counter of iroh guardian dial outcomes per iroh stack (`stable` = iroh 0.35,
/// `next` = iroh 1.0). `result="won"` is the attempt whose connection was
/// returned; `result="error"` is a failed attempt. An attempt still in flight
/// when another stack wins is dropped without being counted.
pub static IROH_STACK_DIALS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "connector_iroh_stack_dials_total",
            "Iroh guardian dial outcomes per iroh stack",
        ),
        &["stack", "result"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Counter of connection attempts, labeled by scheme and result
pub static CONNECTION_ATTEMPTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "connector_connection_attempts_total",
            "Total number of connection attempts to federation peers",
        ),
        &["scheme", "result"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

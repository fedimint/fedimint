use std::sync::LazyLock;

use fedimint_metrics::prometheus::{HistogramVec, register_histogram_vec_with_registry};
use fedimint_metrics::{REGISTRY, histogram_opts};

/// Histogram of HTLC handling durations in seconds
pub static HTLC_HANDLING_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "gateway_htlc_handling_duration_seconds",
            "Duration of HTLC handling in the gateway",
        ),
        &["outcome"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

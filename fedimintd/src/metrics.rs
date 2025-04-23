use std::sync::LazyLock;

use fedimint_metrics::prometheus::{IntGaugeVec, register_int_gauge_vec_with_registry};
use fedimint_metrics::{REGISTRY, opts};

// Note: we can't really use a counter for monitoring restarts of the
// application because such timer would always equal 1, and Prometheus would
// never actually add it up. But what we can do is to use a gauge with a
// timestamp, and then detect every time it changes.
pub(crate) static APP_START_TS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec_with_registry!(
        opts!(
            "app_start_ts",
            "Unix timestamp of the application time with version labels"
        ),
        &["version", "version_hash"],
        REGISTRY
    )
    .unwrap()
});

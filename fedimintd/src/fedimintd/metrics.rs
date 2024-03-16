use fedimint_metrics::prometheus::{register_int_gauge_vec_with_registry, IntGaugeVec};
use fedimint_metrics::{lazy_static, opts, REGISTRY};

lazy_static! {
    // Note: we can't really use a counter for monitoring restarts of the application
    // because such timer would always equal 1, and Prometheus would never actually add
    // it up. But what we can do is to use a gauge with a timestamp, and then detect every time it changes.
    pub(crate) static ref APP_START_TS: IntGaugeVec = register_int_gauge_vec_with_registry!(
        opts!("app_start_ts", "Unix timestamp of the application time with version labels"),
        &["version", "version_hash"],
        REGISTRY
    )
    .unwrap();
}

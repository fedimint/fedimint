use std::sync::LazyLock;

use fedimint_metrics::prometheus::{
    Gauge, HistogramVec, IntGauge, IntGaugeVec, register_gauge_with_registry,
    register_histogram_vec_with_registry, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry,
};
use fedimint_metrics::{REGISTRY, histogram_opts, opts};

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

/// Histogram of LNv2 HTLC handling attempt durations in seconds
pub static HTLC_LNV2_ATTEMPT_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "gateway_htlc_lnv2_attempt_duration_seconds",
            "Duration of LNv2 HTLC handling attempts in the gateway",
        ),
        &["outcome"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Histogram of LNv1 HTLC handling attempt durations in seconds
pub static HTLC_LNV1_ATTEMPT_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "gateway_htlc_lnv1_attempt_duration_seconds",
            "Duration of LNv1 HTLC handling attempts in the gateway",
        ),
        &["outcome"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Percent of assets-at-peak lost since the peak cumulative margin.
pub static GATEWAY_DRAWDOWN_PCT: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge_with_registry!(
        opts!(
            "gateway_drawdown_pct",
            "Forwarding drawdown from peak, percent of assets at peak"
        ),
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Sum of realized forwarding margins across federations, in millisatoshis.
pub static GATEWAY_CUMULATIVE_MARGIN_MSAT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge_with_registry!(
        opts!(
            "gateway_cumulative_margin_msat",
            "Sum of realized forwarding margins across federations"
        ),
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Realized forwarding margin per federation, in millisatoshis.
pub static GATEWAY_FEDERATION_REALIZED_MARGIN_MSAT: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec_with_registry!(
        opts!(
            "gateway_federation_realized_margin_msat",
            "Realized forwarding margin per federation"
        ),
        &["federation_id"],
        REGISTRY
    )
    .expect("metric registration should not fail")
});

/// Cancelled sends the node reports as settled anyway: the state machine's
/// belief about the payment was wrong, and money left despite the refund.
/// Set once per solvency report to the number of phantoms found in that
/// report. A gauge rather than a counter: the ledger is rebuilt from
/// scratch every tick, so every historical phantom is found again on every
/// tick, and a counter would climb by the phantom count every minute
/// forever instead of reflecting how many are currently outstanding.
pub static GATEWAY_PHANTOM_FAILURES: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge_with_registry!(
        opts!(
            "gateway_phantom_failures",
            "Cancelled sends the node reports as settled"
        ),
        REGISTRY
    )
    .expect("metric registration should not fail")
});

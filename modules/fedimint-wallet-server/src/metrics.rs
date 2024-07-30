use std::sync::LazyLock;

use fedimint_metrics::prometheus::{
    register_histogram_vec_with_registry, register_int_gauge_with_registry, IntGauge,
};
use fedimint_metrics::{
    histogram_opts, opts, register_histogram_with_registry, Histogram, HistogramVec,
    AMOUNTS_BUCKETS_SATS, REGISTRY,
};

pub(crate) static WALLET_INOUT_SATS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "wallet_inout_sats",
            "Value of wallet input/out in sats",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        &["direction"],
        REGISTRY
    )
    .unwrap()
});
pub(crate) static WALLET_INOUT_FEES_SATS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "wallet_inout_fees_sats",
            "Value of wallet input/output fees in sats",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        &["direction"],
        REGISTRY
    )
    .unwrap()
});
pub(crate) static WALLET_PEGIN_SATS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram_with_registry!(
        histogram_opts!(
            "wallet_pegin_sats",
            "Value of peg-in transactions in sats (deprecated - prefer wallet_inout_sats)",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        REGISTRY
    )
    .unwrap()
});
pub(crate) static WALLET_PEGIN_FEES_SATS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram_with_registry!(
        histogram_opts!(
            "wallet_pegin_fees_sats",
            "Value of peg-in fees in sats (deprecated - prefer wallet_inout_fees_sats)",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        REGISTRY
    )
    .unwrap()
});
pub(crate) static WALLET_PEGOUT_SATS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram_with_registry!(
        histogram_opts!(
            "wallet_pegout_sats",
            "Value of peg-out transactions in sats (deprecated - prefer wallet_inout_sats)",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        REGISTRY
    )
    .unwrap()
});
pub(crate) static WALLET_PEGOUT_FEES_SATS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram_with_registry!(
        histogram_opts!(
            "wallet_pegout_fees_sats",
            "Value of peg-out fees in sats (deprecated - prefer wallet_inout_fees_sats)",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        REGISTRY
    )
    .unwrap()
});
pub(crate) static WALLET_BLOCK_COUNT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge_with_registry!(
        opts!(
            "wallet_block_count",
            "Blockchain block count as monitored by wallet module",
        ),
        REGISTRY
    )
    .unwrap()
});

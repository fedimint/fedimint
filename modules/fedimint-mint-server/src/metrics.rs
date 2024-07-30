use std::sync::LazyLock;

use fedimint_metrics::prometheus::{
    register_histogram_vec_with_registry, register_histogram_with_registry,
};
use fedimint_metrics::{histogram_opts, Histogram, HistogramVec, AMOUNTS_BUCKETS_SATS, REGISTRY};

pub(crate) static MINT_INOUT_SATS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "mint_inout_sats",
            "Value of input/output e-cash notes in sats",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        &["direction"],
        REGISTRY
    )
    .unwrap()
});
pub(crate) static MINT_INOUT_FEES_SATS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "mint_inout_fees_sats",
            "Value of input/output e-cash fees in sats",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        &["direction"],
        REGISTRY
    )
    .unwrap()
});
pub(crate) static MINT_REDEEMED_ECASH_SATS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram_with_registry!(
        histogram_opts!(
            "mint_redeemed_ecash_sats",
            "Value of redeemed e-cash notes in sats (deprecated - prefer mint_inout_sats)",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        REGISTRY
    )
    .unwrap()
});
pub(crate) static MINT_REDEEMED_ECASH_FEES_SATS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram_with_registry!(
            histogram_opts!(
                "mint_redeemed_ecash_fees_sats",
                "Value of e-cash fees during reissue in sats (deprecated - prefer mint_inout_fees_sats)",
                AMOUNTS_BUCKETS_SATS.clone()
            ),
            REGISTRY
        )
        .unwrap()
});
pub(crate) static MINT_ISSUED_ECASH_SATS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram_with_registry!(
        histogram_opts!(
            "mint_issued_ecash_sats",
            "Value of issued e-cash notes in sats (deprecated - prefer mint_inout_sats)",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        REGISTRY
    )
    .unwrap()
});
pub(crate) static MINT_ISSUED_ECASH_FEES_SATS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram_with_registry!(
        histogram_opts!(
            "mint_issued_ecash_fees_sats",
            "Value of e-cash fees during issue in sats (deprecated - prefer mint_inout_fees_sats)",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        REGISTRY
    )
    .unwrap()
});

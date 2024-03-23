use fedimint_metrics::prometheus::register_histogram_with_registry;
use fedimint_metrics::{histogram_opts, lazy_static, Histogram, AMOUNTS_BUCKETS_SATS, REGISTRY};

lazy_static! {
    pub(crate) static ref MINT_REDEEMED_ECASH_SATS: Histogram = register_histogram_with_registry!(
        histogram_opts!(
            "mint_redeemed_ecash_sats",
            "Value of redeemed e-cash notes in sats",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        REGISTRY
    )
    .unwrap();
    pub(crate) static ref MINT_REDEEMED_ECASH_FEES_SATS: Histogram =
        register_histogram_with_registry!(
            histogram_opts!(
                "mint_redeemed_ecash_fees_sats",
                "Value of e-cash fees during reissue in sats",
                AMOUNTS_BUCKETS_SATS.clone()
            ),
            REGISTRY
        )
        .unwrap();
    pub(crate) static ref MINT_ISSUED_ECASH_SATS: Histogram = register_histogram_with_registry!(
        histogram_opts!(
            "mint_issued_ecash_sats",
            "Value of issued e-cash notes in sats",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        REGISTRY
    )
    .unwrap();
    pub(crate) static ref MINT_ISSUED_ECASH_FEES_SATS: Histogram =
        register_histogram_with_registry!(
            histogram_opts!(
                "mint_issued_ecash_fees_sats",
                "Value of e-cash fees during issue in sats",
                AMOUNTS_BUCKETS_SATS.clone()
            ),
            REGISTRY
        )
        .unwrap();
}

use fedimint_metrics::prometheus::{
    register_histogram_vec_with_registry, register_int_gauge_with_registry, IntGauge,
};
use fedimint_metrics::{
    histogram_opts, lazy_static, opts, register_histogram_with_registry, Histogram, HistogramVec,
    AMOUNTS_BUCKETS_SATS, REGISTRY,
};

lazy_static! {
    pub(crate) static ref WALLET_INOUT_SATS: HistogramVec = register_histogram_vec_with_registry!(
        histogram_opts!(
            "wallet_inout_sats",
            "Value of wallet input/out in sats",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        &[&"direction"],
        REGISTRY
    )
    .unwrap();
    pub(crate) static ref WALLET_INOUT_FEES_SATS: HistogramVec =
        register_histogram_vec_with_registry!(
            histogram_opts!(
                "wallet_inout_fees_sats",
                "Value of wallet input/output fees in sats",
                AMOUNTS_BUCKETS_SATS.clone()
            ),
            &[&"direction"],
            REGISTRY
        )
        .unwrap();
    pub(crate) static ref WALLET_PEGIN_SATS: Histogram = register_histogram_with_registry!(
        histogram_opts!(
            "wallet_pegin_sats",
            "Value of peg-in transactions in sats (deprecated - prefer wallet_inout_sats)",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        REGISTRY
    )
    .unwrap();
    pub(crate) static ref WALLET_PEGIN_FEES_SATS: Histogram = register_histogram_with_registry!(
        histogram_opts!(
            "wallet_pegin_fees_sats",
            "Value of peg-in fees in sats (deprecated - prefer wallet_inout_fees_sats)",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        REGISTRY
    )
    .unwrap();
    pub(crate) static ref WALLET_PEGOUT_SATS: Histogram = register_histogram_with_registry!(
        histogram_opts!(
            "wallet_pegout_sats",
            "Value of peg-out transactions in sats (deprecated - prefer wallet_inout_sats)",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        REGISTRY
    )
    .unwrap();
    pub(crate) static ref WALLET_PEGOUT_FEES_SATS: Histogram = register_histogram_with_registry!(
        histogram_opts!(
            "wallet_pegout_fees_sats",
            "Value of peg-out fees in sats (deprecated - prefer wallet_inout_fees_sats)",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        REGISTRY
    )
    .unwrap();
    pub(crate) static ref WALLET_BLOCK_COUNT: IntGauge = register_int_gauge_with_registry!(
        opts!(
            "wallet_block_count",
            "Blockchain block count as monitored by wallet module",
        ),
        REGISTRY
    )
    .unwrap();
}

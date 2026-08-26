#![allow(clippy::disallowed_types)]
// Prometheus registration macros use `HashMap` internally.

use std::sync::LazyLock;

use fedimint_metrics::prometheus::{
    IntCounterVec, register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
};
use fedimint_metrics::{AMOUNTS_BUCKETS_SATS, HistogramVec, REGISTRY, histogram_opts, opts};

pub(crate) static LN_FUNDED_CONTRACT_SATS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec_with_registry!(
        histogram_opts!(
            "lnv2_funded_contract_sats",
            "Funded (with outgoing or incoming direction) contract amount in sats",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        &["direction"],
        REGISTRY
    )
    .unwrap()
});
pub(crate) static LN_OUTGOING_CONTRACT_SETTLED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "lnv2_outgoing_contract_settled_total",
            "Settled outgoing contracts by outcome (claim, refund or cancel)"
        ),
        &["outcome"],
        REGISTRY
    )
    .unwrap()
});

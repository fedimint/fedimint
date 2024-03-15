use fedimint_metrics::prometheus::{
    register_histogram_vec_with_registry, register_int_counter_with_registry,
};
use fedimint_metrics::{
    histogram_opts, lazy_static, opts, HistogramVec, IntCounter, AMOUNTS_BUCKETS_SATS, REGISTRY,
};

lazy_static! {
    pub static ref LN_INCOMING_OFFER: IntCounter = register_int_counter_with_registry!(
        opts!("ln_incoming_offer_total", "Incoming payment offer"),
        REGISTRY
    )
    .unwrap();
    pub static ref LN_CANCEL_OUTGOING_CONTRACTS: IntCounter = register_int_counter_with_registry!(
        opts!(
            "ln_canceled_outgoing_contract_total",
            "Canceled outgoing contract"
        ),
        REGISTRY
    )
    .unwrap();
    pub static ref LN_FUNDED_CONTRACT_SATS: HistogramVec = register_histogram_vec_with_registry!(
        histogram_opts!(
            "ln_funded_contract_sats",
            "Funded (with outgoing or incoming direction) contract amount in sats",
            AMOUNTS_BUCKETS_SATS.clone()
        ),
        &["direction"],
        REGISTRY
    )
    .unwrap();
}

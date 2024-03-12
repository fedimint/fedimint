use fedimint_metrics::prometheus::{
    register_histogram_vec_with_registry, HistogramVec, IntCounterVec,
};
use fedimint_metrics::{
    histogram_opts, opts, register_histogram_with_registry, register_int_counter_vec_with_registry,
    Histogram, REGISTRY,
};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref TX_ELEMS_BUCKETS: Vec<f64> =
        vec![1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0,];
    pub(crate) static ref CONSENSUS_TX_PROCESSED_INPUTS: Histogram =
        register_histogram_with_registry!(
            histogram_opts!(
                "consensus_tx_processed_inputs",
                "Number of inputs processed in a transaction",
                TX_ELEMS_BUCKETS.clone()
            ),
            REGISTRY
        )
        .unwrap();
    pub(crate) static ref CONSENSUS_TX_PROCESSED_OUTPUTS: Histogram =
        register_histogram_with_registry!(
            histogram_opts!(
                "consensus_tx_processed_outputs",
                "Number of outputs processed in a transaction",
                TX_ELEMS_BUCKETS.clone()
            ),
            REGISTRY
        )
        .unwrap();
    pub(crate) static ref CONSENSUS_ITEMS_PROCESSED_TOTAL: IntCounterVec =
        register_int_counter_vec_with_registry!(
            opts!(
                "consensus_items_processed_total",
                "Number of consensus items processed in the consensus",
            ),
            &["peer_id"],
            REGISTRY
        )
        .unwrap();
    pub(crate) static ref CONSENSUS_ITEM_PROCESSING_DURATION_SECONDS: HistogramVec =
        register_histogram_vec_with_registry!(
            histogram_opts!(
                "consensus_item_processing_duration_seconds",
                "Duration of processing a consensus item",
            ),
            &["peer_id"],
            REGISTRY
        )
        .unwrap();
    pub(crate) static ref CONSENSUS_ITEM_PROCESSING_MODULE_AUDIT_DURATION_SECONDS: HistogramVec =
        register_histogram_vec_with_registry!(
            histogram_opts!(
                "consensus_item_processing_module_audit_duration_seconds",
                "Duration of processing a consensus item",
            ),
            &["module_id", "module_kind"],
            REGISTRY
        )
        .unwrap();
}

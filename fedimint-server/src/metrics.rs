pub(crate) mod jsonrpsee;

use fedimint_core::backup::ClientBackupKeyPrefix;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_metrics::prometheus::{
    register_histogram_vec_with_registry, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec,
};
use fedimint_metrics::{
    histogram_opts, opts, register_histogram_with_registry, register_int_counter_vec_with_registry,
    Histogram, REGISTRY,
};
use futures::StreamExt as _;
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
    pub(crate) static ref JSONRPC_API_REQUEST_DURATION_SECONDS: HistogramVec =
        register_histogram_vec_with_registry!(
            histogram_opts!(
                "jsonrpc_api_request_duration_seconds",
                "Duration of processing an rpc request",
            ),
            &["method"],
            REGISTRY
        )
        .unwrap();
    pub(crate) static ref JSONRPC_API_REQUEST_RESPONSE_CODE: IntCounterVec =
        register_int_counter_vec_with_registry!(
            opts!(
                "jsonrpc_api_request_response_code_total",
                "Count of response counts and types",
            ),
            &["method", "code", "type"],
            REGISTRY
        )
        .unwrap();
    pub(crate) static ref CONSENSUS_SESSION_COUNT: IntGauge = register_int_gauge_with_registry!(
        opts!(
            "consensus_session_count",
            "Fedimint consensus session count",
        ),
        REGISTRY
    )
    .unwrap();
    pub(crate) static ref CONSENSUS_PEER_CONTRIBUTION_SESSION_IDX: IntGaugeVec =
        register_int_gauge_vec_with_registry!(
            opts!(
                "consensus_peer_contribution_session_idx",
                "Latest contribution session idx by peer_id",
            ),
            &["self_id", "peer_id"],
            REGISTRY
        )
        .unwrap();
    pub(crate) static ref BACKUP_WRITE_SIZE_BYTES: Histogram = register_histogram_with_registry!(
        histogram_opts!(
            "backup_write_size_bytes",
            "Size of every backup being written",
            vec![1.0, 10., 100., 1_000., 5_000., 10_000., 50_000., 100_000., 1_000_000.]
        ),
        REGISTRY
    )
    .unwrap();
    pub(crate) static ref STORED_BACKUPS_COUNT: IntGauge = register_int_gauge_with_registry!(
        opts!("stored_backups_count", "Total amount of backups stored",),
        REGISTRY
    )
    .unwrap();
    pub(crate) static ref PEER_CONNECT_COUNT: IntCounterVec =
        register_int_counter_vec_with_registry!(
            opts!("peer_connect_total", "Number of times peer (re/)connected",),
            &["self_id", "peer_id", "direction"],
            REGISTRY
        )
        .unwrap();
    pub(crate) static ref PEER_DISCONNECT_COUNT: IntCounterVec =
        register_int_counter_vec_with_registry!(
            opts!(
                "peer_disconnect_total",
                "Number of times peer (re/)connected",
            ),
            &["self_id", "peer_id"],
            REGISTRY
        )
        .unwrap();
    pub(crate) static ref PEER_MESSAGES_COUNT: IntCounterVec =
        register_int_counter_vec_with_registry!(
            opts!("peer_messages_total", "Messages with the peer",),
            &["self_id", "peer_id", "direction"],
            REGISTRY
        )
        .unwrap();
    pub(crate) static ref PEER_BANS_COUNT: IntCounterVec = register_int_counter_vec_with_registry!(
        opts!("peer_bans_total", "Peer bans",),
        &["self_id", "peer_id"],
        REGISTRY
    )
    .unwrap();
}

/// Initialize gauges or other metrics that need eager initialization on start,
/// e.g. because they are triggered infrequently.
pub(crate) async fn initialize_gauge_metrics(db: &Database) {
    STORED_BACKUPS_COUNT.set(
        db.begin_transaction_nc()
            .await
            .find_by_prefix(&ClientBackupKeyPrefix)
            .await
            .count()
            .await as i64,
    )
}

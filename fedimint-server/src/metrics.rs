pub(crate) mod jsonrpsee;

use std::sync::LazyLock;
use std::time::Duration;

use fedimint_core::backup::ClientBackupKeyPrefix;
use fedimint_core::db::{Database, IReadDatabaseTransactionOpsTyped};
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_metrics::prometheus::{
    HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, register_histogram_vec_with_registry,
    register_int_gauge_vec_with_registry, register_int_gauge_with_registry,
};
use fedimint_metrics::{
    Histogram, REGISTRY, histogram_opts, opts, register_histogram_with_registry,
    register_int_counter_vec_with_registry,
};
use futures::StreamExt as _;
use tokio::sync::OnceCell;

use crate::consensus::api::backup_statistics_static;

const BACKUP_STATS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

pub static TX_ELEMS_BUCKETS: LazyLock<Vec<f64>> = LazyLock::new(|| {
    vec![
        1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0,
    ]
});
pub(crate) static CONSENSUS_TX_PROCESSED_INPUTS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram_with_registry!(
        histogram_opts!(
            "consensus_tx_processed_inputs",
            "Number of inputs processed in a transaction",
            TX_ELEMS_BUCKETS.clone()
        ),
        REGISTRY
    )
    .unwrap()
});
pub(crate) static CONSENSUS_TX_PROCESSED_OUTPUTS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram_with_registry!(
        histogram_opts!(
            "consensus_tx_processed_outputs",
            "Number of outputs processed in a transaction",
            TX_ELEMS_BUCKETS.clone()
        ),
        REGISTRY
    )
    .unwrap()
});
pub(crate) static CONSENSUS_ITEMS_PROCESSED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "consensus_items_processed_total",
            "Number of consensus items processed in the consensus",
        ),
        &["peer_id"],
        REGISTRY
    )
    .unwrap()
});
pub(crate) static CONSENSUS_ITEM_PROCESSING_DURATION_SECONDS: LazyLock<HistogramVec> =
    LazyLock::new(|| {
        register_histogram_vec_with_registry!(
            histogram_opts!(
                "consensus_item_processing_duration_seconds",
                "Duration of processing a consensus item",
            ),
            &["peer_id"],
            REGISTRY
        )
        .unwrap()
    });
pub(crate) static CONSENSUS_ITEM_PROCESSING_MODULE_AUDIT_DURATION_SECONDS: LazyLock<HistogramVec> =
    LazyLock::new(|| {
        register_histogram_vec_with_registry!(
            histogram_opts!(
                "consensus_item_processing_module_audit_duration_seconds",
                "Duration of processing a consensus item",
            ),
            &["module_id", "module_kind"],
            REGISTRY
        )
        .unwrap()
    });

pub(crate) static CONSENSUS_ORDERING_LATENCY_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram_with_registry!(
        histogram_opts!(
            "consensus_ordering_latency_seconds",
            "Duration of ordering a batch of consensus items",
        ),
        REGISTRY
    )
    .unwrap()
});

pub(crate) static JSONRPC_API_REQUEST_DURATION_SECONDS: LazyLock<HistogramVec> =
    LazyLock::new(|| {
        register_histogram_vec_with_registry!(
            histogram_opts!(
                "jsonrpc_api_request_duration_seconds",
                "Duration of processing an rpc request",
            ),
            &["method"],
            REGISTRY
        )
        .unwrap()
    });
pub(crate) static JSONRPC_API_REQUEST_RESPONSE_CODE: LazyLock<IntCounterVec> =
    LazyLock::new(|| {
        register_int_counter_vec_with_registry!(
            opts!(
                "jsonrpc_api_request_response_code_total",
                "Count of response counts and types",
            ),
            &["method", "code", "type"],
            REGISTRY
        )
        .unwrap()
    });
pub(crate) static CONSENSUS_SESSION_COUNT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge_with_registry!(
        opts!(
            "consensus_session_count",
            "Fedimint consensus session count",
        ),
        REGISTRY
    )
    .unwrap()
});
pub(crate) static CONSENSUS_PEER_CONTRIBUTION_SESSION_IDX: LazyLock<IntGaugeVec> =
    LazyLock::new(|| {
        register_int_gauge_vec_with_registry!(
            opts!(
                "consensus_peer_contribution_session_idx",
                "Latest contribution session idx by peer_id",
            ),
            &["self_id", "peer_id"],
            REGISTRY
        )
        .unwrap()
    });
pub(crate) static BACKUP_WRITE_SIZE_BYTES: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram_with_registry!(
        histogram_opts!(
            "backup_write_size_bytes",
            "Size of every backup being written",
            vec![
                1.0, 10., 100., 1_000., 5_000., 10_000., 50_000., 100_000., 1_000_000.
            ]
        ),
        REGISTRY
    )
    .unwrap()
});
pub(crate) static STORED_BACKUPS_COUNT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge_with_registry!(
        opts!("stored_backups_count", "Total amount of backups stored",),
        REGISTRY
    )
    .unwrap()
});

pub(crate) static BACKUP_COUNTS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec_with_registry!(
        opts!(
            "backup_counts",
            "Backups refreshed at least once in a given timeframe",
        ),
        &["timeframe"],
        REGISTRY
    )
    .unwrap()
});

pub(crate) static TOTAL_BACKUP_SIZE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge_with_registry!(
        opts!("total_backup_size", "Total size og backups in the DB",),
        REGISTRY
    )
    .unwrap()
});

/// Lock for spawning exactly one task for updating backup related gauges that
/// are computed fresh from DB regularly instead of being updated incrementally.
static BACKUP_COUNTS_UPDATE_TASK: OnceCell<()> = OnceCell::const_new();

pub(crate) static PEER_CONNECT_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!("peer_connect_total", "Number of times peer (re/)connected",),
        &["self_id", "peer_id", "direction"],
        REGISTRY
    )
    .unwrap()
});
pub(crate) static PEER_DISCONNECT_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!(
            "peer_disconnect_total",
            "Number of times peer (re/)connected",
        ),
        &["self_id", "peer_id"],
        REGISTRY
    )
    .unwrap()
});
pub(crate) static PEER_MESSAGES_COUNT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        opts!("peer_messages_total", "Messages with the peer",),
        &["self_id", "peer_id", "direction"],
        REGISTRY
    )
    .unwrap()
});

/// Initialize gauges or other metrics that need eager initialization on start,
/// e.g. because they are triggered infrequently.
pub(crate) async fn initialize_gauge_metrics(tg: &TaskGroup, db: &Database) {
    STORED_BACKUPS_COUNT.set(
        db.begin_read_transaction()
            .await
            .find_by_prefix(&ClientBackupKeyPrefix)
            .await
            .count()
            .await as i64,
    );

    let db_inner = db.clone();
    BACKUP_COUNTS_UPDATE_TASK
        .get_or_init(move || async move {
            tg.spawn_cancellable("prometheus_backup_stats", async move {
                loop {
                    let backup_counts =
                        backup_statistics_static(&mut db_inner.begin_read_transaction().await)
                            .await;

                    BACKUP_COUNTS.with_label_values(&["1d"]).set(
                        backup_counts
                            .refreshed_1d
                            .try_into()
                            .expect("u64 to i64 overflow"),
                    );
                    BACKUP_COUNTS.with_label_values(&["1w"]).set(
                        backup_counts
                            .refreshed_1w
                            .try_into()
                            .expect("u64 to i64 overflow"),
                    );
                    BACKUP_COUNTS.with_label_values(&["1m"]).set(
                        backup_counts
                            .refreshed_1m
                            .try_into()
                            .expect("u64 to i64 overflow"),
                    );
                    BACKUP_COUNTS.with_label_values(&["3m"]).set(
                        backup_counts
                            .refreshed_3m
                            .try_into()
                            .expect("u64 to i64 overflow"),
                    );
                    BACKUP_COUNTS.with_label_values(&["all_time"]).set(
                        backup_counts
                            .num_backups
                            .try_into()
                            .expect("u64 to i64 overflow"),
                    );

                    TOTAL_BACKUP_SIZE.set(
                        backup_counts
                            .total_size
                            .try_into()
                            .expect("u64 to i64 overflow"),
                    );

                    sleep(BACKUP_STATS_REFRESH_INTERVAL).await;
                }
            });
        })
        .await;
}

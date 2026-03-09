//! Visualization data structures and data-fetching for client internals.
//!
//! Provides structured data for operations and transactions that can be
//! formatted by downstream consumers (CLI, GUI, etc.).
//!
//! Each data struct implements [`fmt::Display`] for text rendering.
//! Consumers who want custom formatting can use the public fields directly.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fedimint_client_module::oplog::OperationLogEntry;
use fedimint_client_module::sm::{ActiveStateMeta, DynState, IState, InactiveStateMeta};
use fedimint_client_module::transaction::{
    TRANSACTION_SUBMISSION_MODULE_INSTANCE, TxSubmissionStates, TxSubmissionStatesSM,
};
use fedimint_core::TransactionId;
use fedimint_core::core::{ModuleInstanceId, OperationId};
use time::OffsetDateTime;

use crate::Client;

/// Visualization data for a single operation and its state machines.
pub struct OperationVisData {
    pub operation_id: OperationId,
    pub creation_time: Option<SystemTime>,
    pub operation_type: String,
    pub has_outcome: bool,
    pub states: Vec<StateVisData>,
}

/// Visualization data for a single state machine entry.
pub struct StateVisData {
    pub is_active: bool,
    pub module_id: ModuleInstanceId,
    pub module_kind: String,
    pub created_at: SystemTime,
    pub exited_at: Option<SystemTime>,
    pub visualization: String,
}

/// Visualization data for transactions grouped under one operation.
pub struct OperationTransactionsVisData {
    pub operation_id: OperationId,
    pub operation_type: String,
    pub transactions: Vec<TransactionVisData>,
}

/// Visualization data for a single transaction.
pub struct TransactionVisData {
    pub txid: TransactionId,
    pub status: TransactionVisStatus,
    pub created_at: Option<SystemTime>,
    pub inputs: Vec<TxIoVisData>,
    pub outputs: Vec<TxIoVisData>,
}

/// Status of a transaction for visualization purposes.
pub enum TransactionVisStatus {
    Pending,
    Accepted,
    Rejected(String),
    Completed(String),
}

/// Visualization data for a transaction input or output.
pub struct TxIoVisData {
    pub module_id: ModuleInstanceId,
    pub module_kind: String,
    pub display: String,
}

/// Look up the kind name for a module instance ID.
pub fn module_kind_name(kinds: &BTreeMap<ModuleInstanceId, String>, id: ModuleInstanceId) -> &str {
    kinds.get(&id).map_or("unknown", String::as_str)
}

// ─── Formatting helpers ─────────────────────────────────────────────────────

/// Format a `SystemTime` as ISO8601 with second precision.
pub fn systime_to_iso8601_secs(t: &SystemTime) -> String {
    use time::format_description::well_known::iso8601::{
        Config, FormattedComponents, TimePrecision,
    };

    const ISO8601_SECS: time::format_description::well_known::iso8601::EncodedConfig =
        Config::DEFAULT
            .set_formatted_components(FormattedComponents::DateTime)
            .set_time_precision(TimePrecision::Second {
                decimal_digits: None,
            })
            .encode();

    OffsetDateTime::from_unix_timestamp_nanos(
        t.duration_since(UNIX_EPOCH)
            .expect("before unix epoch")
            .as_nanos()
            .try_into()
            .expect("time overflowed"),
    )
    .expect("couldn't convert SystemTime to OffsetDateTime")
    .format(&time::format_description::well_known::Iso8601::<ISO8601_SECS>)
    .expect("couldn't format as ISO8601")
}

/// Format a microsecond Unix timestamp as ISO8601 with second precision.
pub fn usecs_to_iso8601_secs(ts: u64) -> String {
    systime_to_iso8601_secs(&(UNIX_EPOCH + Duration::from_micros(ts)))
}

/// Format a `Duration` for display (e.g. "42ms" or "1.234s").
pub fn duration_display(d: Duration) -> String {
    let total_ms = d.as_millis();
    if total_ms < 1000 {
        format!("{total_ms}ms")
    } else {
        let s = d.as_secs();
        let ms = d.subsec_millis();
        format!("{s}.{ms:03}s")
    }
}

// ─── Display impls ──────────────────────────────────────────────────────────

impl fmt::Display for TransactionVisStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Accepted => write!(f, "accepted"),
            Self::Rejected(err) => write!(f, "rejected: {err}"),
            Self::Completed(s) => write!(f, "{s}"),
        }
    }
}

impl fmt::Display for TxIoVisData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mod={} ({}) {}",
            self.module_id, self.module_kind, self.display
        )
    }
}

impl fmt::Display for TransactionVisData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(created_at) = &self.created_at {
            let ts = systime_to_iso8601_secs(created_at);
            writeln!(f, "  tx {} [{}]  {ts}", self.txid.fmt_short(), self.status)?;
        } else {
            writeln!(f, "  tx {} [{}]", self.txid.fmt_short(), self.status)?;
        }

        if self.inputs.is_empty() && self.outputs.is_empty() {
            writeln!(f, "    (transaction data not available)")?;
        } else {
            if !self.inputs.is_empty() {
                writeln!(f, "    inputs:")?;
                for (i, item) in self.inputs.iter().enumerate() {
                    writeln!(f, "      [{i}] {item}")?;
                }
            }
            if !self.outputs.is_empty() {
                writeln!(f, "    outputs:")?;
                for (i, item) in self.outputs.iter().enumerate() {
                    writeln!(f, "      [{i}] {item}")?;
                }
            }
        }
        Ok(())
    }
}

impl fmt::Display for OperationTransactionsVisData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "### Transactions for op {} ({})\n",
            self.operation_id.fmt_full(),
            self.operation_type
        )?;

        if self.transactions.is_empty() {
            writeln!(f, "  (no transactions found)")?;
        }

        for tx in &self.transactions {
            write!(f, "{tx}")?;
        }
        writeln!(f)
    }
}

impl fmt::Display for StateVisData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.is_active { "active" } else { "done  " };
        let dur = self.exited_at.and_then(|ex| {
            ex.duration_since(self.created_at)
                .ok()
                .map(|d| format!(" ({})", duration_display(d)))
        });

        write!(
            f,
            "    [{status}] ({}) {}{}\n             {}",
            self.module_kind,
            systime_to_iso8601_secs(&self.created_at),
            dur.unwrap_or_default(),
            self.visualization,
        )
    }
}

impl fmt::Display for OperationVisData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ts = self
            .creation_time
            .as_ref()
            .map_or_else(|| "-".to_string(), systime_to_iso8601_secs);
        let status = if self.has_outcome { "done" } else { "pending" };

        writeln!(
            f,
            "### Operation {} ({}) {ts} [{status}]\n",
            self.operation_id.fmt_short(),
            self.operation_type
        )?;

        if self.states.is_empty() {
            writeln!(f, "  (no state machines)")?;
        }

        for state in &self.states {
            writeln!(f, "{state}")?;
        }
        writeln!(f)
    }
}

/// Complete operations visualization output, ready for display.
///
/// Wraps `Vec<OperationVisData>` and adds numbered listing in the `Display`
/// impl.
pub struct OperationsVisOutput(pub Vec<OperationVisData>);

impl fmt::Display for OperationsVisOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            writeln!(f, "  (no operations)")?;
            return Ok(());
        }

        for op in &self.0 {
            write!(f, "{op}")?;
        }
        Ok(())
    }
}

/// Complete transactions visualization output, ready for display.
pub struct TransactionsVisOutput(pub Vec<OperationTransactionsVisData>);

impl fmt::Display for TransactionsVisOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for op in &self.0 {
            write!(f, "{op}")?;
        }
        Ok(())
    }
}

/// Find the final status of a transaction from its state machines.
fn find_tx_final_status(
    active: &[(DynState, ActiveStateMeta)],
    inactive: &[(DynState, InactiveStateMeta)],
    target_txid: TransactionId,
) -> Option<String> {
    let check_state = |s: &DynState| -> Option<String> {
        if s.module_instance_id() != TRANSACTION_SUBMISSION_MODULE_INSTANCE {
            return None;
        }
        let sm = s.as_any().downcast_ref::<TxSubmissionStatesSM>()?;
        match &sm.state {
            TxSubmissionStates::Accepted(id) if *id == target_txid => Some("accepted".to_string()),
            TxSubmissionStates::Rejected(id, err) if *id == target_txid => {
                Some(format!("rejected: {err}"))
            }
            _ => None,
        }
    };

    // Check inactive states first (more likely to have final status)
    for (s, _) in inactive {
        if let Some(status) = check_state(s) {
            return Some(status);
        }
    }
    for (s, _) in active {
        if let Some(status) = check_state(s) {
            return Some(status);
        }
    }
    None
}

impl Client {
    /// Build a map from module instance ID to kind name.
    async fn sm_module_to_string_map(&self) -> BTreeMap<ModuleInstanceId, String> {
        let config = self.config().await;
        let mut map: BTreeMap<ModuleInstanceId, String> = config
            .modules
            .iter()
            .map(|(id, cfg)| (*id, cfg.kind.to_string()))
            .collect();
        map.insert(TRANSACTION_SUBMISSION_MODULE_INSTANCE, "tx".to_string());
        map
    }

    /// Resolve operations: either a single explicit one, or the most recent
    /// `limit` from the operation log.
    async fn resolve_operations(
        &self,
        explicit: Option<OperationId>,
        limit: Option<usize>,
    ) -> anyhow::Result<Vec<(OperationId, Option<SystemTime>, OperationLogEntry)>> {
        if let Some(id) = explicit {
            let entry = self
                .operation_log()
                .get_operation(id)
                .await
                .ok_or_else(|| anyhow::anyhow!("Operation not found"))?;
            return Ok(vec![(id, None, entry)]);
        }
        let ops = self
            .operation_log()
            .paginate_operations_rev(limit.unwrap_or(usize::MAX), None)
            .await;
        Ok(ops
            .into_iter()
            .map(|(k, entry)| (k.operation_id, Some(k.creation_time), entry))
            .collect())
    }

    /// Fetch visualization data for operations and their state machines.
    pub async fn get_operations_vis(
        &self,
        operation_id: Option<OperationId>,
        limit: Option<usize>,
    ) -> anyhow::Result<Vec<OperationVisData>> {
        let ops: Vec<(OperationId, Option<SystemTime>, OperationLogEntry)> =
            self.resolve_operations(operation_id, limit).await?;
        let kinds = self.sm_module_to_string_map().await;

        let mut result = Vec::with_capacity(ops.len());

        for (op_id, creation_time, entry) in ops {
            let (active, inactive) = self.executor().get_operation_states(op_id).await;

            let mut states: Vec<StateVisData> = Vec::new();

            for (state, meta) in &active {
                states.push(StateVisData {
                    is_active: true,
                    module_id: state.module_instance_id(),
                    module_kind: module_kind_name(&kinds, state.module_instance_id()).to_string(),
                    created_at: meta.created_at,
                    exited_at: None,
                    visualization: state.visualization(""),
                });
            }

            for (state, meta) in &inactive {
                states.push(StateVisData {
                    is_active: false,
                    module_id: state.module_instance_id(),
                    module_kind: module_kind_name(&kinds, state.module_instance_id()).to_string(),
                    created_at: meta.created_at,
                    exited_at: Some(meta.exited_at),
                    visualization: state.visualization(""),
                });
            }

            states.sort_by_key(|e| e.created_at);

            result.push(OperationVisData {
                operation_id: op_id,
                creation_time,
                operation_type: entry.operation_module_kind().to_string(),
                has_outcome: entry.outcome::<serde_json::Value>().is_some(),
                states,
            });
        }

        Ok(result)
    }

    /// Fetch visualization data for transactions grouped by operation.
    pub async fn get_transactions_vis(
        &self,
        operation_id: Option<OperationId>,
        limit: Option<usize>,
    ) -> anyhow::Result<Vec<OperationTransactionsVisData>> {
        let ops: Vec<(OperationId, Option<SystemTime>, OperationLogEntry)> =
            self.resolve_operations(operation_id, limit).await?;
        let kinds = self.sm_module_to_string_map().await;

        let mut result = Vec::with_capacity(ops.len());

        for (op_id, _, entry) in ops {
            let (active, inactive) = self.executor().get_operation_states(op_id).await;

            let mut transactions = Vec::new();
            let mut seen_txids = HashSet::new();

            // Collect from inactive Created states first (have full tx data and
            // final status)
            for (state, meta) in &inactive {
                if state.module_instance_id() != TRANSACTION_SUBMISSION_MODULE_INSTANCE {
                    continue;
                }
                let Some(tx_sm) = state.as_any().downcast_ref::<TxSubmissionStatesSM>() else {
                    continue;
                };
                let TxSubmissionStates::Created(tx) = &tx_sm.state else {
                    continue;
                };

                let txid: TransactionId = tx.tx_hash();
                let final_status = find_tx_final_status(&active, &inactive, txid);
                let status = match final_status {
                    Some(s) if s == "accepted" => TransactionVisStatus::Accepted,
                    Some(s) if s.starts_with("rejected: ") => {
                        TransactionVisStatus::Rejected(s["rejected: ".len()..].to_string())
                    }
                    Some(s) => TransactionVisStatus::Completed(s),
                    None => TransactionVisStatus::Completed("completed".to_string()),
                };

                let inputs = tx
                    .inputs
                    .iter()
                    .map(|input| TxIoVisData {
                        module_id: input.module_instance_id(),
                        module_kind: module_kind_name(&kinds, input.module_instance_id())
                            .to_string(),
                        display: input.to_string(),
                    })
                    .collect();

                let outputs = tx
                    .outputs
                    .iter()
                    .map(|output| TxIoVisData {
                        module_id: output.module_instance_id(),
                        module_kind: module_kind_name(&kinds, output.module_instance_id())
                            .to_string(),
                        display: output.to_string(),
                    })
                    .collect();

                transactions.push(TransactionVisData {
                    txid,
                    status,
                    created_at: Some(meta.created_at),
                    inputs,
                    outputs,
                });
                seen_txids.insert(txid);
            }

            // Active Created states (still pending)
            for (state, meta) in &active {
                if state.module_instance_id() != TRANSACTION_SUBMISSION_MODULE_INSTANCE {
                    continue;
                }
                let Some(tx_sm) = state.as_any().downcast_ref::<TxSubmissionStatesSM>() else {
                    continue;
                };
                let TxSubmissionStates::Created(tx) = &tx_sm.state else {
                    continue;
                };

                let txid: TransactionId = tx.tx_hash();
                if seen_txids.contains(&txid) {
                    continue;
                }

                let inputs = tx
                    .inputs
                    .iter()
                    .map(|input| TxIoVisData {
                        module_id: input.module_instance_id(),
                        module_kind: module_kind_name(&kinds, input.module_instance_id())
                            .to_string(),
                        display: input.to_string(),
                    })
                    .collect();

                let outputs = tx
                    .outputs
                    .iter()
                    .map(|output| TxIoVisData {
                        module_id: output.module_instance_id(),
                        module_kind: module_kind_name(&kinds, output.module_instance_id())
                            .to_string(),
                        display: output.to_string(),
                    })
                    .collect();

                transactions.push(TransactionVisData {
                    txid,
                    status: TransactionVisStatus::Pending,
                    created_at: Some(meta.created_at),
                    inputs,
                    outputs,
                });
                seen_txids.insert(txid);
            }

            // Final states without a Created variant (no full tx data)
            let all_for_final = inactive
                .iter()
                .map(|(s, _)| s)
                .chain(active.iter().map(|(s, _)| s));

            for state in all_for_final {
                if state.module_instance_id() != TRANSACTION_SUBMISSION_MODULE_INSTANCE {
                    continue;
                }
                let Some(tx_sm) = state.as_any().downcast_ref::<TxSubmissionStatesSM>() else {
                    continue;
                };
                match &tx_sm.state {
                    TxSubmissionStates::Accepted(txid) if !seen_txids.contains(txid) => {
                        transactions.push(TransactionVisData {
                            txid: *txid,
                            status: TransactionVisStatus::Accepted,
                            created_at: None,
                            inputs: vec![],
                            outputs: vec![],
                        });
                        seen_txids.insert(*txid);
                    }
                    TxSubmissionStates::Rejected(txid, err) if !seen_txids.contains(txid) => {
                        transactions.push(TransactionVisData {
                            txid: *txid,
                            status: TransactionVisStatus::Rejected(err.clone()),
                            created_at: None,
                            inputs: vec![],
                            outputs: vec![],
                        });
                        seen_txids.insert(*txid);
                    }
                    _ => {}
                }
            }

            result.push(OperationTransactionsVisData {
                operation_id: op_id,
                operation_type: entry.operation_module_kind().to_string(),
                transactions,
            });
        }

        Ok(result)
    }
}

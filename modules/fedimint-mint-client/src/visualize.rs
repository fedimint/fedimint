//! Visualization data structures and data-fetching for mint e-cash notes.
//!
//! Provides [`NoteVisData`] with creation/spending provenance for each note,
//! collected from the wallet DB, operation state machines, and event log.
//!
//! [`NoteVisData`] and [`NotesVisOutput`] implement [`fmt::Display`] for text
//! rendering.

use std::collections::HashMap;
use std::fmt;

use fedimint_client::Client;
use fedimint_client::visualize::usecs_to_iso8601_secs;
use fedimint_client_module::sm::IState;
use fedimint_client_module::transaction::{
    TRANSACTION_SUBMISSION_MODULE_INSTANCE, TxSubmissionStates, TxSubmissionStatesSM,
};
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::{Amount, TransactionId};
use futures::StreamExt;

use crate::client_db::NoteKeyPrefix;
use crate::event::{NoteCreated, NoteSpent};
use crate::{BlindNonce, MintClientModule, MintClientStateMachines, MintInput, Nonce};

/// Per-nonce record with creation and spending provenance.
pub struct NoteVisData {
    pub nonce: Nonce,
    pub amount: Option<Amount>,
    pub blind_nonce: Option<BlindNonce>,
    pub created_op: Option<OperationId>,
    pub created_txid: Option<TransactionId>,
    pub created_out_idx: Option<u64>,
    pub created_ts: Option<u64>,
    pub spent_op: Option<OperationId>,
    pub spent_txid: Option<TransactionId>,
    pub spent_in_idx: Option<usize>,
    pub spent_ts: Option<u64>,
    pub in_wallet: bool,
}

#[derive(Default)]
struct NoteRecord {
    amount: Option<Amount>,
    blind_nonce: Option<BlindNonce>,
    created_op: Option<OperationId>,
    created_txid: Option<TransactionId>,
    created_out_idx: Option<u64>,
    created_ts: Option<u64>,
    spent_op: Option<OperationId>,
    spent_txid: Option<TransactionId>,
    spent_in_idx: Option<usize>,
    spent_ts: Option<u64>,
    in_wallet: bool,
}

/// Fetch note visualization data from client state.
///
/// Scans the wallet DB, operation state machines, and event log for the
/// `limit` most recent operations.
pub async fn get_notes_vis(client: &Client, limit: Option<usize>) -> NotesVisOutput {
    let ops = client
        .operation_log()
        .paginate_operations_rev(limit.unwrap_or(usize::MAX), None)
        .await;
    let ops_count = ops.len();

    let mut notes: HashMap<Nonce, NoteRecord> = HashMap::new();

    // 1. Scan wallet DB for current notes (nonce + amount)
    if let Ok(mint_instance) = client.get_first_module::<MintClientModule>() {
        let mut dbtx = mint_instance.db.begin_transaction_nc().await;
        let wallet_notes: Vec<_> = dbtx.find_by_prefix(&NoteKeyPrefix).await.collect().await;
        for (key, _note) in wallet_notes {
            let record = notes.entry(key.nonce).or_default();
            record.amount = Some(key.amount);
            record.in_wallet = true;
        }
    }

    // 2. Scan operations' state machines
    for (key, _entry) in &ops {
        scan_operation_states(client, key.operation_id, &mut notes).await;
    }

    // 3. Scan entire event log for NoteCreated and NoteSpent events
    scan_event_log(client, &mut notes).await;

    // 4. Sort by creation time and convert to NoteVisData
    let mut entries: Vec<_> = notes.into_iter().collect();
    entries.sort_by_key(|(_, r)| r.created_ts.unwrap_or(0));

    let notes = entries
        .into_iter()
        .map(|(nonce, r)| NoteVisData {
            nonce,
            amount: r.amount,
            blind_nonce: r.blind_nonce,
            created_op: r.created_op,
            created_txid: r.created_txid,
            created_out_idx: r.created_out_idx,
            created_ts: r.created_ts,
            spent_op: r.spent_op,
            spent_txid: r.spent_txid,
            spent_in_idx: r.spent_in_idx,
            spent_ts: r.spent_ts,
            in_wallet: r.in_wallet,
        })
        .collect();

    NotesVisOutput { notes, ops_count }
}

/// Extract note creation/spending info from an operation's state machines.
async fn scan_operation_states(
    client: &Client,
    op_id: OperationId,
    notes: &mut HashMap<Nonce, NoteRecord>,
) {
    let (active, inactive) = client.executor().get_operation_states(op_id).await;

    let all_states = active
        .iter()
        .map(|(s, _)| s)
        .chain(inactive.iter().map(|(s, _)| s));

    for state in all_states {
        // TxSubmission states → extract spending info from MintInput
        if state.module_instance_id() == TRANSACTION_SUBMISSION_MODULE_INSTANCE {
            let Some(tx_sm) = state.as_any().downcast_ref::<TxSubmissionStatesSM>() else {
                continue;
            };
            let TxSubmissionStates::Created(tx) = &tx_sm.state else {
                continue;
            };

            let txid: TransactionId = tx.tx_hash();

            for (idx, input) in tx.inputs.iter().enumerate() {
                if let Some(mint_input) = input.as_any().downcast_ref::<MintInput>()
                    && let Some(v0) = mint_input.maybe_v0_ref()
                {
                    let nonce = v0.note.nonce;
                    let record = notes.entry(nonce).or_default();
                    record.amount = Some(v0.amount);
                    record.spent_op = Some(op_id);
                    record.spent_txid = Some(txid);
                    record.spent_in_idx = Some(idx);
                }
            }
            continue;
        }

        // Mint output state machines → extract creation info
        if let Some(MintClientStateMachines::Output(sm)) =
            state.as_any().downcast_ref::<MintClientStateMachines>()
        {
            let txid = sm.txid();
            for (out_idx, amount, nonce, blind_nonce) in sm.created_nonces() {
                let record = notes.entry(nonce).or_default();
                record.amount = Some(amount);
                record.blind_nonce = Some(blind_nonce);
                record.created_op = Some(op_id);
                record.created_txid = Some(txid);
                record.created_out_idx = Some(out_idx);
            }
        }
    }
}

/// Paginate through the entire event log, recording note timestamps.
async fn scan_event_log(client: &Client, notes: &mut HashMap<Nonce, NoteRecord>) {
    const PAGE_SIZE: u64 = 10000;
    let mut cursor = None;
    loop {
        let page = client.get_event_log(cursor, PAGE_SIZE).await;
        if page.entries.is_empty() {
            break;
        }
        for event in &page.entries {
            if event.kind == fedimint_eventlog::EventKind::from_static("note-created") {
                if let Some(nc) = event.to_event::<NoteCreated>() {
                    let record = notes.entry(nc.nonce).or_default();
                    record.created_ts = Some(event.ts_usecs);
                }
            } else if event.kind == fedimint_eventlog::EventKind::from_static("note-spent")
                && let Some(ns) = event.to_event::<NoteSpent>()
            {
                let record = notes.entry(ns.nonce).or_default();
                record.spent_ts = Some(event.ts_usecs);
            }
        }
        cursor = Some(page.next_cursor);
    }
}

/// Complete notes visualization output, ready for display.
pub struct NotesVisOutput {
    pub notes: Vec<NoteVisData>,
    pub ops_count: usize,
}

impl fmt::Display for NoteVisData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let amount_str = self.amount.map_or("?".to_string(), |a| a.msats.to_string());
        let blind_nonce_str = self.blind_nonce.map_or(String::new(), |bn| {
            format!("  blind_nonce={}", bn.fmt_short())
        });
        writeln!(
            f,
            "nonce={}{}  amount={amount_str}",
            self.nonce.fmt_short(),
            blind_nonce_str
        )?;

        // Creation info
        let when_created = self
            .created_ts
            .map_or("?".to_string(), usecs_to_iso8601_secs);
        if let (Some(op), Some(txid), Some(idx)) =
            (self.created_op, self.created_txid, self.created_out_idx)
        {
            writeln!(
                f,
                "    created: {when_created}  op={}  tx={}:{idx}",
                op.fmt_short(),
                txid.fmt_short()
            )?;
        } else {
            writeln!(f, "    created: {when_created}")?;
        }

        // Spending info (only if spent)
        if let (Some(op), Some(txid), Some(idx)) =
            (self.spent_op, self.spent_txid, self.spent_in_idx)
        {
            let when_spent = self.spent_ts.map_or("?".to_string(), usecs_to_iso8601_secs);
            writeln!(
                f,
                "    spent:   {when_spent}  op={}  tx={}:{idx}",
                op.fmt_short(),
                txid.fmt_short()
            )?;
        } else if let Some(ts) = self.spent_ts {
            writeln!(
                f,
                "    spent:   {}  (no tx info in recent ops)",
                usecs_to_iso8601_secs(ts)
            )?;
        }
        Ok(())
    }
}

impl fmt::Display for NotesVisOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "### Notes ({} found, from {} most recent operations + event log)\n",
            self.notes.len(),
            self.ops_count
        )?;

        if self.notes.is_empty() {
            writeln!(f, "  (no notes found)")?;
            return Ok(());
        }

        for note in &self.notes {
            write!(f, "{note}")?;
        }
        writeln!(f)
    }
}

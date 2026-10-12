use std::collections::{BTreeMap, BTreeSet};

use bitcoin_hashes::hash160;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, impl_db_lookup, impl_db_record};
use fedimint_mintv2_common::Denomination;
use strum::Display;
use strum_macros::EnumIter;

use crate::SpendableNote;
use crate::issuance::NoteIssuanceRequest;

#[repr(u8)]
#[derive(Clone, Display, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Note = 0x20,
    RecoveryState = 0x21,
    PendingRebalanceCause = 0x22,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SpendableNoteKey(pub SpendableNote);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SpendableNotePrefix;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct SpendableNoteAmountPrefix(pub Denomination);

impl_db_record!(
    key = SpendableNoteKey,
    value = (),
    db_prefix = DbKeyPrefix::Note,
);

impl_db_lookup!(key = SpendableNoteKey, query_prefix = SpendableNotePrefix);

impl_db_lookup!(
    key = SpendableNoteKey,
    query_prefix = SpendableNoteAmountPrefix
);

/// A send that left a denomination below its minimum, awaiting a rebalance.
///
/// Recorded inside the same transaction as the send, so it exists exactly when
/// the spend that caused it committed. The `denomination_deficit` is the number
/// of notes a rebalance needs to restore each affected denomination to its
/// target.
#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable)]
pub struct PendingRebalanceCause {
    /// The send operation that spent the notes.
    pub operation_id: OperationId,
    /// Value of the spent notes.
    pub spent_amount: Amount,
    /// Notes each affected denomination needs to reach its target.
    pub denomination_deficit: BTreeMap<Denomination, u64>,
    /// When the send committed, in seconds since the Unix epoch.
    pub created_at: u64,
}

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PendingRebalanceCauseKey(pub OperationId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct PendingRebalanceCausePrefix;

impl_db_record!(
    key = PendingRebalanceCauseKey,
    value = PendingRebalanceCause,
    db_prefix = DbKeyPrefix::PendingRebalanceCause,
);

impl_db_lookup!(
    key = PendingRebalanceCauseKey,
    query_prefix = PendingRebalanceCausePrefix
);

/// Key for storing recovery progress state
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RecoveryStateKey;

/// Recovery state that can be checkpointed and resumed
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RecoveryState {
    /// Next item index to download
    pub next_index: u64,
    /// Total items (for progress calculation)
    pub total_items: u64,
    /// Already recovered note requests, keyed by `nonce_hash` (for efficient
    /// removal when inputs are seen)
    pub requests: BTreeMap<hash160::Hash, NoteIssuanceRequest>,
    /// Nonces seen (to detect duplicates)
    pub nonces: BTreeSet<hash160::Hash>,
}

impl_db_record!(
    key = RecoveryStateKey,
    value = RecoveryState,
    db_prefix = DbKeyPrefix::RecoveryState,
);

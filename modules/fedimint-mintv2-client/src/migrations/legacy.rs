//! The shape the recovery checkpoint had before its requests carried an
//! account.

use std::collections::{BTreeMap, BTreeSet};

use bitcoin_hashes::hash160;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;

use crate::client_db::DbKeyPrefix;
use crate::issuance::NoteIssuanceRequest;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RecoveryStateKey;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RecoveryState {
    pub next_index: u64,
    pub total_items: u64,
    pub requests: BTreeMap<hash160::Hash, NoteIssuanceRequest>,
    pub nonces: BTreeSet<hash160::Hash>,
}

impl_db_record!(
    key = RecoveryStateKey,
    value = RecoveryState,
    db_prefix = DbKeyPrefix::RecoveryState,
);

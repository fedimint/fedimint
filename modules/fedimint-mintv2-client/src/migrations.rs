//! Client database migrations.

use fedimint_core::core::{Account, OperationId};
use fedimint_core::db::{
    DatabaseTransaction, DbMigrationError, IDatabaseTransactionOpsCore,
    IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::Decodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use futures::StreamExt;

use crate::SpendableNote;
use crate::client_db::{DbKeyPrefix, RecoveryState, RecoveryStateKey, SpendableNoteKey};

/// Accounts split the note table, so every note a pre-accounts client wrote is
/// re-keyed as belonging to [`Account::Primary`] — the only account it could
/// have meant.
///
/// Neither the derivation tree nor the state machines need an equivalent:
/// primary derives exactly where it always did, so no note has to be
/// re-issued, and a state machine reads its account off its operation rather
/// than carrying it, so the ones in flight keep their shape.
pub(crate) async fn migrate_to_accounts_v1(
    dbtx: &mut DatabaseTransaction<'_>,
    _active_states: Vec<(Vec<u8>, OperationId)>,
    _inactive_states: Vec<(Vec<u8>, OperationId)>,
) -> Result<Option<(Vec<(Vec<u8>, OperationId)>, Vec<(Vec<u8>, OperationId)>)>, DbMigrationError> {
    // Read raw: the old key is the note alone, so decoding one through the
    // current two-field key would read the note's leading denomination byte as
    // an account and fail. The rows are rewritten rather than edited in place.
    let prefix = vec![DbKeyPrefix::Note as u8];

    let notes = dbtx
        .raw_find_by_prefix(&prefix)
        .await?
        .map(|(key, _)| key)
        .collect::<Vec<Vec<u8>>>()
        .await;

    for key in notes {
        let note = SpendableNote::consensus_decode_whole(
            &key[prefix.len()..],
            &ModuleDecoderRegistry::default(),
        )?;

        dbtx.raw_remove_entry(&key).await?;

        dbtx.insert_new_entry(&SpendableNoteKey(Account::Primary, note), &())
            .await;
    }

    // Recovery keeps its scanned requests tagged with an account now. A
    // pre-accounts checkpoint can only have scanned primary's subtree, so it
    // is carried over with every request tagged primary and its progress
    // intact. Restarting the scan from zero instead would re-derive the notes
    // a client in usable recovery has minted since the scan's bound and try
    // to insert them a second time.
    if let Some(state) = dbtx.remove_entry(&legacy::RecoveryStateKey).await {
        let state = RecoveryState {
            next_index: state.next_index,
            total_items: state.total_items,
            requests: state
                .requests
                .into_iter()
                .map(|(nonce_hash, request)| (nonce_hash, (Account::Primary, request)))
                .collect(),
            nonces: state.nonces,
        };

        dbtx.insert_new_entry(&RecoveryStateKey, &state).await;
    }

    Ok(None)
}

/// The shape the recovery checkpoint had before its requests carried an
/// account.
mod legacy {
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
}

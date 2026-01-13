use std::collections::BTreeMap;

use fedimint_core::db::DatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, PeerId, impl_db_lookup, impl_db_record, push_db_pair_items};
use fedimint_ecash_migration_common::merkle::MerkleRoot;
use fedimint_ecash_migration_common::{KeySetHash, TransferId};
use fedimint_mint_common::Nonce;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use tbs::AggregatePublicKey;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    TransferMetadata = 0x01,
    OutPointTransferId = 0x02,
    UploadedSpendBookEntries = 0x03,
    OriginSpendBook = 0x04,
    LocalSpendBook = 0x05,
    ActivationVote = 0x06,
    ActivationRequest = 0x07,
    DenominationKeys = 0x08,
    DepositedAmount = 0x09,
    WithdrawnAmount = 0x0a,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Metadata about a transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize)]
pub struct TransferMetadata {
    /// Merkle root for verifiable chunk uploads
    pub origin_spend_book_merkle_root: MerkleRoot<Nonce>,
    /// Hash of the key set to be uploaded
    pub origin_key_set_hash: KeySetHash,
    /// Number of spend book entries in the origin spend book that will be
    /// uploaded.
    ///
    /// The creator of the transfer is supposed to pay for this quota to limit
    /// denial of service risk, hence it's fixed upfront.
    pub num_spend_book_entries: u64,
}

/// Key for [`TransferMetadata`] entries
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct TransferMetadataKey(pub TransferId);

/// Prefix for querying all [`TransferMetadata`] entries
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct TransferMetadataKeyPrefix;

impl_db_record!(
    key = TransferMetadataKey,
    value = TransferMetadata,
    db_prefix = DbKeyPrefix::TransferMetadata,
);

impl_db_lookup!(
    key = TransferMetadataKey,
    query_prefix = TransferMetadataKeyPrefix,
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct OutPointTransferIdKey(pub OutPoint);

impl_db_record!(
    key = OutPointTransferIdKey,
    value = TransferId,
    db_prefix = DbKeyPrefix::OutPointTransferId,
);

/// Prefix for querying all [`OutPointTransferIdKey`] entries
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct OutPointTransferIdPrefix;

impl_db_lookup!(
    key = OutPointTransferIdKey,
    query_prefix = OutPointTransferIdPrefix,
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
/// Contains the number of spend book entries that have been uploaded for a
/// transfer already. Used to prevent uploading more than were paid for.
pub struct UploadedSpendBookEntriesKey {
    pub transfer_id: TransferId,
}

impl_db_record!(
    key = UploadedSpendBookEntriesKey,
    value = u64,
    db_prefix = DbKeyPrefix::UploadedSpendBookEntries,
);

/// Prefix for querying all [`UploadedSpendBookEntriesKey`] entries
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct UploadedSpendBookEntriesPrefix;
impl_db_lookup!(
    key = UploadedSpendBookEntriesKey,
    query_prefix = UploadedSpendBookEntriesPrefix,
);

/// Key for [`OriginSpendBookKey`] entries. Each entry represents an already
/// spent note in the origin federation that cannot be redeemed anymore.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize)]
pub struct OriginSpendBookKey {
    pub transfer_id: TransferId,
    pub nonce: Nonce,
}

impl_db_record!(
    key = OriginSpendBookKey,
    value = (),
    db_prefix = DbKeyPrefix::OriginSpendBook,
);

/// Prefix for querying all [`OriginSpendBookKey`] entries for a transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct OriginSpendBookTransferPrefix {
    pub transfer_id: TransferId,
}
impl_db_lookup!(
    key = OriginSpendBookKey,
    query_prefix = OriginSpendBookTransferPrefix,
);

/// Prefix for querying all [`OriginSpendBookKey`] entries
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct OriginSpendBookPrefix;
impl_db_lookup!(
    key = OriginSpendBookKey,
    query_prefix = OriginSpendBookPrefix,
);

/// Key for [`LocalSpendBookKey`] entries. Each entry represents a note that has
/// been redeemed othis federation.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct LocalSpendBookKey {
    pub transfer_id: TransferId,
    pub nonce: Nonce,
}

impl_db_record!(
    key = LocalSpendBookKey,
    value = Amount,
    db_prefix = DbKeyPrefix::LocalSpendBook,
);

/// Prefix for querying all [`LocalSpendBookKey`] entries for a transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct LocalSpendBookTransferPrefix {
    pub transfer_id: TransferId,
}
impl_db_lookup!(
    key = LocalSpendBookKey,
    query_prefix = LocalSpendBookTransferPrefix,
);

/// Prefix for querying all [`LocalSpendBookKey`] entries
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct LocalSpendBookPrefix;
impl_db_lookup!(key = LocalSpendBookKey, query_prefix = LocalSpendBookPrefix,);

/// Vote from a peer for transfer activation. Once all peers have voted, the
/// transfer is activated (note that this is quite different from the usual
/// consensus mechanism where only a thresholf of the peers need to agree on the
/// same value).
#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize)]
pub struct ActivationVote;

/// Key for activation votes
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ActivationVoteKey {
    pub transfer_id: TransferId,
    pub peer_id: PeerId,
}

impl_db_record!(
    key = ActivationVoteKey,
    value = ActivationVote,
    db_prefix = DbKeyPrefix::ActivationVote,
);

/// Prefix for querying all [`ActivationVote`] entries belonging to a specific
/// transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct ActivationVoteTransferPrefix {
    pub transfer_id: TransferId,
}

impl_db_lookup!(
    key = ActivationVoteKey,
    query_prefix = ActivationVoteTransferPrefix,
);

/// Prefix for querying all [`ActivationVote`] entries
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct ActivationVotePrefix;

impl_db_lookup!(key = ActivationVoteKey, query_prefix = ActivationVotePrefix,);

/// User-requested activation of a transfer, not confirmed by consensus yet
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ActivationRequestKey {
    pub transfer_id: TransferId,
}

impl_db_record!(
    key = ActivationRequestKey,
    value = (),
    db_prefix = DbKeyPrefix::ActivationRequest,
);

/// Prefix for querying all activation requests
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct ActivationRequestPrefix;

impl_db_lookup!(
    key = ActivationRequestKey,
    query_prefix = ActivationRequestPrefix,
);

/// Key for tier public keys
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct DenominationKeyKey {
    pub transfer_id: TransferId,
    pub amount: Amount,
}

/// Prefix for querying all denomination keys for a transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct DenominationKeyKeyTransferPrefix {
    pub transfer_id: TransferId,
}
impl_db_lookup!(
    key = DenominationKeyKey,
    query_prefix = DenominationKeyKeyTransferPrefix,
);

/// Prefix for querying all denomination keys for a transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct DenominationKeyKeyPrefix;
impl_db_lookup!(
    key = DenominationKeyKey,
    query_prefix = DenominationKeyKeyPrefix,
);

impl_db_record!(
    key = DenominationKeyKey,
    value = AggregatePublicKey,
    db_prefix = DbKeyPrefix::DenominationKeys,
);

/// Prefix for querying all tier keys for a transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct TierKeyPrefix {
    pub transfer_id: TransferId,
}

impl_db_lookup!(key = DenominationKeyKey, query_prefix = TierKeyPrefix,);

/// Key for deposited amount
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct DepositedAmountKey(pub TransferId);

impl_db_record!(
    key = DepositedAmountKey,
    value = Amount,
    db_prefix = DbKeyPrefix::DepositedAmount,
);

/// Prefix for querying all deposited amounts
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct DepositedAmountPrefix;

impl_db_lookup!(
    key = DepositedAmountKey,
    query_prefix = DepositedAmountPrefix,
);

/// Key for withdrawn amount
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct WithdrawnAmountKey(pub TransferId);

impl_db_record!(
    key = WithdrawnAmountKey,
    value = Amount,
    db_prefix = DbKeyPrefix::WithdrawnAmount,
);

/// Prefix for querying all withdrawn amounts
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct WithdrawnAmountPrefix;

impl_db_lookup!(
    key = WithdrawnAmountKey,
    query_prefix = WithdrawnAmountPrefix,
);

#[allow(clippy::too_many_lines)]
pub(crate) async fn dump_database(
    dbtx: &mut DatabaseTransaction<'_>,
    prefix_names: Vec<String>,
) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)>> {
    let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
    let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
        prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
    });

    for table in filtered_prefixes {
        match table {
            DbKeyPrefix::TransferMetadata => {
                push_db_pair_items!(
                    dbtx,
                    TransferMetadataKeyPrefix,
                    TransferMetadataKey,
                    TransferMetadata,
                    items,
                    "Transfer Metadata"
                );
            }
            DbKeyPrefix::OutPointTransferId => {
                push_db_pair_items!(
                    dbtx,
                    OutPointTransferIdPrefix,
                    OutPointTransferIdKey,
                    TransferId,
                    items,
                    "Out Point Transfer ID"
                );
            }
            DbKeyPrefix::UploadedSpendBookEntries => {
                push_db_pair_items!(
                    dbtx,
                    UploadedSpendBookEntriesPrefix,
                    UploadedSpendBookEntriesKey,
                    u64,
                    items,
                    "Uploaded Spend Book Entries"
                );
            }
            DbKeyPrefix::OriginSpendBook => {
                push_db_pair_items!(
                    dbtx,
                    OriginSpendBookPrefix,
                    OriginSpendBookKey,
                    (),
                    items,
                    "Origin Spend Book"
                );
            }
            DbKeyPrefix::LocalSpendBook => {
                push_db_pair_items!(
                    dbtx,
                    LocalSpendBookPrefix,
                    LocalSpendBookKey,
                    Amount,
                    items,
                    "Local Spend Book"
                );
            }
            DbKeyPrefix::ActivationVote => {
                push_db_pair_items!(
                    dbtx,
                    ActivationVotePrefix,
                    ActivationVoteKey,
                    ActivationVote,
                    items,
                    "Activation Vote"
                );
            }
            DbKeyPrefix::ActivationRequest => {
                push_db_pair_items!(
                    dbtx,
                    ActivationRequestPrefix,
                    ActivationRequestKey,
                    (),
                    items,
                    "Activation Request"
                );
            }
            DbKeyPrefix::DenominationKeys => {
                push_db_pair_items!(
                    dbtx,
                    DenominationKeyKeyPrefix,
                    DenominationKeyKey,
                    AggregatePublicKey,
                    items,
                    "Denomination Keys"
                );
            }
            DbKeyPrefix::DepositedAmount => {
                push_db_pair_items!(
                    dbtx,
                    DepositedAmountPrefix,
                    DepositedAmountKey,
                    Amount,
                    items,
                    "Deposited Amount"
                );
            }
            DbKeyPrefix::WithdrawnAmount => {
                push_db_pair_items!(
                    dbtx,
                    WithdrawnAmountPrefix,
                    WithdrawnAmountKey,
                    Amount,
                    items,
                    "Withdrawn Amount"
                );
            }
        }
    }

    Box::new(items.into_iter())
}

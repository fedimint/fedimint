use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, PeerId, impl_db_lookup, impl_db_record};
use fedimint_ecash_migration_common::naive_threshold::NaiveThresholdKey;
use fedimint_ecash_migration_common::{KeySetHash, SpendBookHash, TransferId};
use fedimint_mint_common::Nonce;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;
use tbs::AggregatePublicKey;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    TransferMetadata = 0x01,
    OutPointTransferId = 0x02,
    OriginSpendBook = 0x03,
    LocalSpendBook = 0x04,
    ActivationVote = 0x05,
    ActivationRequest = 0x06,
    DenominationKeys = 0x07,
    DepositedAmount = 0x08,
    WithdrawnAmount = 0x09,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Metadata about a liabiity transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize)]
pub struct TransferMetadata {
    /// Pre-committed spend book hash (set at creation time)
    pub origin_spend_book_hash: SpendBookHash,
    pub origin_key_set_hash: KeySetHash,
    /// Number of spend book entries in the origin spend book that will be
    /// uploaded.
    ///
    /// The creator of the transfer is supposed to pay for this quota to limit
    /// denial of service risk, hence it's fixed upfront.
    pub num_spend_book_entries: u64,
    /// Threshold public keys for the creator of the transfer
    pub creator_keys: NaiveThresholdKey,
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

/// Prefix for querying all [`OutPointTransferId`] entries
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct OutPointTransferIdPrefix;

impl_db_lookup!(
    key = OutPointTransferIdKey,
    query_prefix = OutPointTransferIdPrefix,
);

/// Key for [`OriginSpendBook`] entries. Each entry represents an already spent
/// note in the origin federation that cannot be redeemed anymore.
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

/// Prefix for querying all [`OriginSpendBook`] entries for a transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct OriginSpendBookTransferPrefix {
    pub transfer_id: TransferId,
}
impl_db_lookup!(
    key = OriginSpendBookKey,
    query_prefix = OriginSpendBookTransferPrefix,
);

/// Prefix for querying all [`OriginSpendBook`] entries
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct OriginSpendBookPrefix;
impl_db_lookup!(
    key = OriginSpendBookKey,
    query_prefix = OriginSpendBookPrefix,
);

/// Key for [`LocalSpendBook`] entries. Each entry represents a note that has
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

/// Prefix for querying all [`LocalSpendBook`] entries for a transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct LocalSpendBookTransferPrefix {
    pub transfer_id: TransferId,
}
impl_db_lookup!(
    key = LocalSpendBookKey,
    query_prefix = LocalSpendBookTransferPrefix,
);

/// Prefix for querying all [`LocalSpendBook`] entries
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

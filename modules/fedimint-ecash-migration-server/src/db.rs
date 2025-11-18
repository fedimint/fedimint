use bitcoin_hashes::sha256;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, InPoint, PeerId, impl_db_lookup, impl_db_record};
use fedimint_ecash_migration_common::{
    OriginFederationKeys, SpendBookHash, TransferId, TransferPhase,
};
use fedimint_mint_common::Nonce;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

/// Namespaces DB keys for this module
#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    /// Transfer metadata
    TransferMetadata = 0x10,
    /// Spend book entries (nonces from origin federation)
    SpendBookEntry = 0x20,
    /// Redeemed nonces (prevent double-spending)
    RedeemedNonce = 0x30,
    /// Activation votes from peers
    ActivationVote = 0x40,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Metadata about a transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize)]
pub struct TransferMetadata {
    /// HMAC-SHA256 hash of the trusted party's secret
    pub secret_hash: sha256::Hash,
    /// Current phase of the transfer
    pub phase: TransferPhase,
    /// Origin federation public keys for signature verification
    pub origin_keys: OriginFederationKeys,
    /// Hash of the spend book (set when finalized)
    pub spend_book_hash: Option<SpendBookHash>,
    /// Total liability from spend book
    pub total_liability: Amount,
}

/// Key for transfer metadata
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct TransferMetadataKey(pub TransferId);

/// Prefix for querying all transfer metadata
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

/// Key for spend book entries
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize)]
pub struct SpendBookEntryKey {
    pub transfer_id: TransferId,
    pub nonce: Nonce,
}

impl_db_record!(
    key = SpendBookEntryKey,
    value = Amount,
    db_prefix = DbKeyPrefix::SpendBookEntry,
);

/// Prefix for querying all spend book entries for a transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct SpendBookEntryPrefix {
    pub transfer_id: TransferId,
}

impl_db_lookup!(key = SpendBookEntryKey, query_prefix = SpendBookEntryPrefix,);

/// Key for redeemed nonces
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct RedeemedNonceKey {
    pub transfer_id: TransferId,
    pub nonce: Nonce,
}

impl_db_record!(
    key = RedeemedNonceKey,
    value = InPoint,
    db_prefix = DbKeyPrefix::RedeemedNonce,
);

/// Prefix for querying all redeemed nonces for a transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct RedeemedNoncePrefix {
    pub transfer_id: TransferId,
}

impl_db_lookup!(key = RedeemedNonceKey, query_prefix = RedeemedNoncePrefix,);

/// Vote from a peer for transfer activation
#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize)]
pub struct ActivationVote {
    pub spend_book_hash: SpendBookHash,
    pub total_amount: Amount,
}

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

/// Prefix for querying all activation votes for a transfer
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct ActivationVotePrefix {
    pub transfer_id: TransferId,
}

impl_db_lookup!(key = ActivationVoteKey, query_prefix = ActivationVotePrefix,);

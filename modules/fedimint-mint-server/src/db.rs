use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, impl_db_lookup, impl_db_record};
use fedimint_mint_common::{BlindNonce, MintOutputOutcome, Nonce, RecoveryItem};
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    NoteNonce = 0x10,
    OutputOutcome = 0x13,
    MintAuditItem = 0x14,
    // 0x15 was previously used for e-cash backups, but removed in DB migration 1
    BlindNonce = 0x16,
    RecoveryItem = 0x17,
    RecoveryBlindNonceOutpoint = 0x18,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Index for all the spent e-cash note nonces to prevent double spends.
/// **Extremely safety critical!**
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct NonceKey(pub Nonce);

#[derive(Debug, Encodable, Decodable)]
pub struct NonceKeyPrefix;

impl_db_record!(
    key = NonceKey,
    value = (),
    db_prefix = DbKeyPrefix::NoteNonce,
);
impl_db_lookup!(key = NonceKey, query_prefix = NonceKeyPrefix);

/// Index for all the previously used blind nonces. Just a safety net for
/// clients to not accidentally burn money.
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct BlindNonceKey(pub BlindNonce);

#[derive(Debug, Encodable, Decodable)]
pub struct BlindNonceKeyPrefix;

impl_db_record!(
    key = BlindNonceKey,
    value = (),
    db_prefix = DbKeyPrefix::BlindNonce,
);
impl_db_lookup!(key = BlindNonceKey, query_prefix = BlindNonceKeyPrefix);

/// Transaction id and output index identifying an output outcome
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct MintOutputOutcomeKey(pub OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct MintOutputOutcomePrefix;

impl_db_record!(
    key = MintOutputOutcomeKey,
    value = MintOutputOutcome,
    db_prefix = DbKeyPrefix::OutputOutcome,
);
impl_db_lookup!(
    key = MintOutputOutcomeKey,
    query_prefix = MintOutputOutcomePrefix
);

/// Represents the amounts of issued (signed) and redeemed (verified) notes for
/// auditing
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub enum MintAuditItemKey {
    Issuance(OutPoint),
    IssuanceTotal,
    Redemption(NonceKey),
    RedemptionTotal,
}

#[derive(Debug, Encodable, Decodable)]
pub struct MintAuditItemKeyPrefix;

impl_db_record!(
    key = MintAuditItemKey,
    value = Amount,
    db_prefix = DbKeyPrefix::MintAuditItem,
);
impl_db_lookup!(
    key = MintAuditItemKey,
    query_prefix = MintAuditItemKeyPrefix
);

#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct RecoveryItemKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct RecoveryItemKeyPrefix;

impl_db_record!(
    key = RecoveryItemKey,
    value = RecoveryItem,
    db_prefix = DbKeyPrefix::RecoveryItem,
);
impl_db_lookup!(key = RecoveryItemKey, query_prefix = RecoveryItemKeyPrefix);

/// Maps blind nonce to outpoint for recovery
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct RecoveryBlindNonceOutpointKey(pub BlindNonce);

#[derive(Debug, Encodable, Decodable)]
pub struct RecoveryBlindNonceOutpointKeyPrefix;

impl_db_record!(
    key = RecoveryBlindNonceOutpointKey,
    value = OutPoint,
    db_prefix = DbKeyPrefix::RecoveryBlindNonceOutpoint,
);
impl_db_lookup!(
    key = RecoveryBlindNonceOutpointKey,
    query_prefix = RecoveryBlindNonceOutpointKeyPrefix
);

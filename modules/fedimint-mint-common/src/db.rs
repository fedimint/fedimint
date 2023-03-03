use std::time::SystemTime;

use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, Amount, OutPoint, PeerId};
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::{MintOutputBlindSignatures, MintOutputSignatureShare, Nonce};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    NoteNonce = 0x10,
    ProposedPartialSig = 0x11,
    ReceivedPartialSig = 0x12,
    OutputOutcome = 0x13,
    MintAuditItem = 0x14,
    EcashBackup = 0x15,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

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

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ProposedPartialSignatureKey {
    pub out_point: OutPoint, // tx + output idx
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedPartialSignaturesKeyPrefix;

impl_db_record!(
    key = ProposedPartialSignatureKey,
    value = MintOutputSignatureShare,
    db_prefix = DbKeyPrefix::ProposedPartialSig,
);
impl_db_lookup!(
    key = ProposedPartialSignatureKey,
    query_prefix = ProposedPartialSignaturesKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ReceivedPartialSignatureKey {
    pub request_id: OutPoint, // tx + output idx
    pub peer_id: PeerId,
}

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignaturesKeyPrefix;

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignatureKeyOutputPrefix {
    pub request_id: OutPoint, // tx + output idx
}

impl_db_record!(
    key = ReceivedPartialSignatureKey,
    value = MintOutputSignatureShare,
    db_prefix = DbKeyPrefix::ReceivedPartialSig,
);
impl_db_lookup!(
    key = ReceivedPartialSignatureKey,
    query_prefix = ReceivedPartialSignaturesKeyPrefix,
    query_prefix = ReceivedPartialSignatureKeyOutputPrefix
);

/// Transaction id and output index identifying an output outcome
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct OutputOutcomeKey(pub OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct OutputOutcomeKeyPrefix;

impl_db_record!(
    key = OutputOutcomeKey,
    value = MintOutputBlindSignatures,
    db_prefix = DbKeyPrefix::OutputOutcome,
);
impl_db_lookup!(
    key = OutputOutcomeKey,
    query_prefix = OutputOutcomeKeyPrefix
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

/// Key used to store user's ecash backups
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct EcashBackupKey(pub secp256k1_zkp::XOnlyPublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct EcashBackupKeyPrefix;

impl_db_record!(
    key = EcashBackupKey,
    value = ECashUserBackupSnapshot,
    db_prefix = DbKeyPrefix::EcashBackup,
);
impl_db_lookup!(key = EcashBackupKey, query_prefix = EcashBackupKeyPrefix);

/// User's backup, received at certain time, containing encrypted payload
#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable, Serialize, Deserialize)]
pub struct ECashUserBackupSnapshot {
    pub timestamp: SystemTime,
    #[serde(with = "fedimint_core::hex::serde")]
    pub data: Vec<u8>,
}

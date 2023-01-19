use std::time::SystemTime;

use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::{Amount, OutPoint, PeerId};
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::{MintOutputBlindSignatures, MintOutputSignatureShare, Nonce};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    CoinNonce = 0x10,
    ProposedPartialSig = 0x11,
    ReceivedPartialSig = 0x12,
    OutputOutcome = 0x13,
    MintAuditItem = 0x14,
    EcashBackup = 0x15,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct NonceKey(pub Nonce);

impl DatabaseKeyPrefixConst for NonceKey {
    const DB_PREFIX: u8 = DbKeyPrefix::CoinNonce as u8;
    type Key = Self;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable)]
pub struct NonceKeyPrefix;

impl DatabaseKeyPrefixConst for NonceKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::CoinNonce as u8;
    type Key = NonceKey;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ProposedPartialSignatureKey {
    pub out_point: OutPoint, // tx + output idx
}

impl DatabaseKeyPrefixConst for ProposedPartialSignatureKey {
    const DB_PREFIX: u8 = DbKeyPrefix::ProposedPartialSig as u8;
    type Key = Self;
    type Value = MintOutputSignatureShare;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedPartialSignaturesKeyPrefix;

impl DatabaseKeyPrefixConst for ProposedPartialSignaturesKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::ProposedPartialSig as u8;
    type Key = ProposedPartialSignatureKey;
    type Value = MintOutputSignatureShare;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ReceivedPartialSignatureKey {
    pub request_id: OutPoint, // tx + output idx
    pub peer_id: PeerId,
}

impl DatabaseKeyPrefixConst for ReceivedPartialSignatureKey {
    const DB_PREFIX: u8 = DbKeyPrefix::ReceivedPartialSig as u8;
    type Key = Self;
    type Value = MintOutputSignatureShare;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignatureKeyOutputPrefix {
    pub request_id: OutPoint, // tx + output idx
}

impl DatabaseKeyPrefixConst for ReceivedPartialSignatureKeyOutputPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::ReceivedPartialSig as u8;
    type Key = ReceivedPartialSignatureKey;
    type Value = MintOutputSignatureShare;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignaturesKeyPrefix;

impl DatabaseKeyPrefixConst for ReceivedPartialSignaturesKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::ReceivedPartialSig as u8;
    type Key = ReceivedPartialSignatureKey;
    type Value = MintOutputSignatureShare;
}

/// Transaction id and output index identifying an output outcome
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct OutputOutcomeKey(pub OutPoint);

impl DatabaseKeyPrefixConst for OutputOutcomeKey {
    const DB_PREFIX: u8 = DbKeyPrefix::OutputOutcome as u8;
    type Key = Self;
    type Value = MintOutputBlindSignatures;
}

#[derive(Debug, Encodable, Decodable)]
pub struct OutputOutcomeKeyPrefix;

impl DatabaseKeyPrefixConst for OutputOutcomeKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::OutputOutcome as u8;
    type Key = OutputOutcomeKey;
    type Value = MintOutputBlindSignatures;
}

/// Represents the amounts of issued (signed) and redeemed (verified) coins for auditing
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub enum MintAuditItemKey {
    Issuance(OutPoint),
    IssuanceTotal,
    Redemption(NonceKey),
    RedemptionTotal,
}

impl DatabaseKeyPrefixConst for MintAuditItemKey {
    const DB_PREFIX: u8 = DbKeyPrefix::MintAuditItem as u8;
    type Key = Self;
    type Value = Amount;
}

#[derive(Debug, Encodable, Decodable)]
pub struct MintAuditItemKeyPrefix;

impl DatabaseKeyPrefixConst for MintAuditItemKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::MintAuditItem as u8;
    type Key = MintAuditItemKey;
    type Value = Amount;
}

#[derive(Debug, Encodable, Decodable)]
pub struct EcashBackupKeyPrefix;

/// Key used to store user's ecash backups
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct EcashBackupKey(pub secp256k1_zkp::XOnlyPublicKey);

impl DatabaseKeyPrefixConst for EcashBackupKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::EcashBackup as u8;
    type Key = EcashBackupKey;
    type Value = ECashUserBackupSnapshot;
}

/// User's backup, received at certain time, containing encrypted payload
#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable, Serialize, Deserialize)]
pub struct ECashUserBackupSnapshot {
    pub timestamp: SystemTime,
    #[serde(with = "fedimint_api::hex::serde")]
    pub data: Vec<u8>,
}

impl DatabaseKeyPrefixConst for EcashBackupKey {
    const DB_PREFIX: u8 = DbKeyPrefix::EcashBackup as u8;
    type Key = Self;
    type Value = ECashUserBackupSnapshot;
}

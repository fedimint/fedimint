use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::{Amount, OutPoint, PeerId};

use crate::{Nonce, PartialSigResponse, SigResponse};

#[repr(u8)]
#[derive(Clone)]
pub enum DbKeyPrefix {
    CoinNonce = 0x10,
    ProposedPartialSig = 0x11,
    ReceivedPartialSig = 0x12,
    OutputOutcome = 0x13,
    MintAuditItem = 0x14,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct NonceKey(pub Nonce);

impl DatabaseKeyPrefixConst for NonceKey {
    const DB_PREFIX: u8 = DbKeyPrefix::CoinNonce as u8;
    type Key = Self;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedPartialSignatureKey {
    pub request_id: OutPoint, // tx + output idx
}

impl DatabaseKeyPrefixConst for ProposedPartialSignatureKey {
    const DB_PREFIX: u8 = DbKeyPrefix::ProposedPartialSig as u8;
    type Key = Self;
    type Value = PartialSigResponse;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedPartialSignaturesKeyPrefix;

impl DatabaseKeyPrefixConst for ProposedPartialSignaturesKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::ProposedPartialSig as u8;
    type Key = ProposedPartialSignatureKey;
    type Value = PartialSigResponse;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignatureKey {
    pub request_id: OutPoint, // tx + output idx
    pub peer_id: PeerId,
}

impl DatabaseKeyPrefixConst for ReceivedPartialSignatureKey {
    const DB_PREFIX: u8 = DbKeyPrefix::ReceivedPartialSig as u8;
    type Key = Self;
    type Value = PartialSigResponse;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignatureKeyOutputPrefix {
    pub request_id: OutPoint, // tx + output idx
}

impl DatabaseKeyPrefixConst for ReceivedPartialSignatureKeyOutputPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::ReceivedPartialSig as u8;
    type Key = ReceivedPartialSignatureKey;
    type Value = PartialSigResponse;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignaturesKeyPrefix;

impl DatabaseKeyPrefixConst for ReceivedPartialSignaturesKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::ReceivedPartialSig as u8;
    type Key = ReceivedPartialSignatureKey;
    type Value = PartialSigResponse;
}

/// Transaction id and output index identifying an output outcome
#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct OutputOutcomeKey(pub OutPoint);

impl DatabaseKeyPrefixConst for OutputOutcomeKey {
    const DB_PREFIX: u8 = DbKeyPrefix::OutputOutcome as u8;
    type Key = Self;
    type Value = SigResponse;
}

/// Represents the amounts of issued (signed) and redeemed (verified) coins for auditing
#[derive(Debug, Clone, Encodable, Decodable)]
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

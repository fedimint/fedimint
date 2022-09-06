use crate::{Nonce, PartialSigResponse, SigResponse};
use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::{Amount, OutPoint, PeerId};

const DB_PREFIX_COIN_NONCE: u8 = 0x10;
const DB_PREFIX_PROPOSED_PARTIAL_SIG: u8 = 0x11;
const DB_PREFIX_RECEIVED_PARTIAL_SIG: u8 = 0x12;
const DB_PREFIX_OUTPUT_OUTCOME: u8 = 0x13;
const DB_PREFIX_MINT_AUDIT_ITEM: u8 = 0x14;

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct NonceKey(pub Nonce);

impl DatabaseKeyPrefixConst for NonceKey {
    const DB_PREFIX: u8 = DB_PREFIX_COIN_NONCE;
    type Key = Self;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedPartialSignatureKey {
    pub request_id: OutPoint, // tx + output idx
}

impl DatabaseKeyPrefixConst for ProposedPartialSignatureKey {
    const DB_PREFIX: u8 = DB_PREFIX_PROPOSED_PARTIAL_SIG;
    type Key = Self;
    type Value = PartialSigResponse;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedPartialSignaturesKeyPrefix;

impl DatabaseKeyPrefixConst for ProposedPartialSignaturesKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_PROPOSED_PARTIAL_SIG;
    type Key = ProposedPartialSignatureKey;
    type Value = PartialSigResponse;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignatureKey {
    pub request_id: OutPoint, // tx + output idx
    pub peer_id: PeerId,
}

impl DatabaseKeyPrefixConst for ReceivedPartialSignatureKey {
    const DB_PREFIX: u8 = DB_PREFIX_RECEIVED_PARTIAL_SIG;
    type Key = Self;
    type Value = PartialSigResponse;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignatureKeyOutputPrefix {
    pub request_id: OutPoint, // tx + output idx
}

impl DatabaseKeyPrefixConst for ReceivedPartialSignatureKeyOutputPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_RECEIVED_PARTIAL_SIG;
    type Key = ReceivedPartialSignatureKey;
    type Value = PartialSigResponse;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignaturesKeyPrefix;

impl DatabaseKeyPrefixConst for ReceivedPartialSignaturesKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_RECEIVED_PARTIAL_SIG;
    type Key = ReceivedPartialSignatureKey;
    type Value = PartialSigResponse;
}

/// Transaction id and output index identifying an output outcome
#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct OutputOutcomeKey(pub OutPoint);

impl DatabaseKeyPrefixConst for OutputOutcomeKey {
    const DB_PREFIX: u8 = DB_PREFIX_OUTPUT_OUTCOME;
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
    const DB_PREFIX: u8 = DB_PREFIX_MINT_AUDIT_ITEM;
    type Key = Self;
    type Value = Amount;
}

#[derive(Debug, Encodable, Decodable)]
pub struct MintAuditItemKeyPrefix;

impl DatabaseKeyPrefixConst for MintAuditItemKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_MINT_AUDIT_ITEM;
    type Key = MintAuditItemKey;
    type Value = Amount;
}

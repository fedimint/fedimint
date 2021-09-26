use minimint_api::db::DatabaseKeyPrefixConst;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::transaction::OutPoint;
use minimint_api::CoinNonce;

const DB_PREFIX_COIN_NONCE: u8 = 0x10;
const DB_PREFIX_PROPOSED_PARTIAL_SIG: u8 = 0x11;
const DB_PREFIX_RECEIVED_PARTIAL_SIG: u8 = 0x12;
const DB_PREFIX_OUTPUT_OUTCOME: u8 = 0x13;

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct NonceKey(pub CoinNonce);

impl DatabaseKeyPrefixConst for NonceKey {
    const DB_PREFIX: u8 = DB_PREFIX_COIN_NONCE;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedPartialSignatureKey {
    pub request_id: OutPoint, // tx + output idx
}

impl DatabaseKeyPrefixConst for ProposedPartialSignatureKey {
    const DB_PREFIX: u8 = DB_PREFIX_PROPOSED_PARTIAL_SIG;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedPartialSignaturesKeyPrefix;

impl DatabaseKeyPrefixConst for ProposedPartialSignaturesKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_PROPOSED_PARTIAL_SIG;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignatureKey {
    pub request_id: OutPoint, // tx + output idx
    pub peer_id: u16,
}

impl DatabaseKeyPrefixConst for ReceivedPartialSignatureKey {
    const DB_PREFIX: u8 = DB_PREFIX_RECEIVED_PARTIAL_SIG;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignatureKeyOutputPrefix {
    pub request_id: OutPoint, // tx + output idx
}

impl DatabaseKeyPrefixConst for ReceivedPartialSignatureKeyOutputPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_RECEIVED_PARTIAL_SIG;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignaturesKeyPrefix;

impl DatabaseKeyPrefixConst for ReceivedPartialSignaturesKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_RECEIVED_PARTIAL_SIG;
}

/// Transaction id and output index identifying an output outcome
#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct OutputOutcomeKey(pub OutPoint);

impl DatabaseKeyPrefixConst for OutputOutcomeKey {
    const DB_PREFIX: u8 = DB_PREFIX_OUTPUT_OUTCOME;
}

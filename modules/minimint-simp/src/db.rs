use crate::contracts::account::AccountContract;
use crate::contracts::incoming::{IncomingContractOffer, PreimageDecryptionShare};
use crate::contracts::ContractId;
use crate::OutputOutcome;
use minimint_api::db::DatabaseKeyPrefixConst;
use minimint_api::encoding::{Decodable, Encodable};
use minimint_api::{OutPoint, PeerId};

const DB_PREFIX_CONTRACT: u8 = 0x40;
const DB_PREFIX_OFFER: u8 = 0x41;
const DB_PREFIX_PROPOSE_DECRYPTION_SHARE: u8 = 0x42;
const DB_PREFIX_AGREED_DECRYPTION_SHARE: u8 = 0x43;
const DB_PREFIX_CONTRACT_UPDATE: u8 = 0x44;

#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct ContractKey(pub ContractId);

impl DatabaseKeyPrefixConst for ContractKey {
    const DB_PREFIX: u8 = DB_PREFIX_CONTRACT;
    type Key = Self;
    type Value = AccountContract;
}

#[derive(Debug, Encodable, Decodable)]
pub struct ContractUpdateKey(pub OutPoint);

impl DatabaseKeyPrefixConst for ContractUpdateKey {
    const DB_PREFIX: u8 = DB_PREFIX_CONTRACT_UPDATE;
    type Key = Self;
    type Value = OutputOutcome;
}

#[derive(Debug, Encodable, Decodable)]
pub struct OfferKey(pub bitcoin_hashes::sha256::Hash);

impl DatabaseKeyPrefixConst for OfferKey {
    const DB_PREFIX: u8 = DB_PREFIX_OFFER;
    type Key = Self;
    type Value = IncomingContractOffer;
}

#[derive(Debug, Encodable, Decodable)]
pub struct OfferKeyPrefix;

impl DatabaseKeyPrefixConst for OfferKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_OFFER;
    type Key = OfferKey;
    type Value = IncomingContractOffer;
}

// TODO: remove redundancy
#[derive(Debug, Encodable, Decodable)]
pub struct ProposeDecryptionShareKey(pub ContractId);

impl DatabaseKeyPrefixConst for ProposeDecryptionShareKey {
    const DB_PREFIX: u8 = DB_PREFIX_PROPOSE_DECRYPTION_SHARE;
    type Key = Self;
    type Value = PreimageDecryptionShare;
}

/// Our preimage decryption shares that still need to be broadcasted
#[derive(Debug, Encodable)]
pub struct ProposeDecryptionShareKeyPrefix;

impl DatabaseKeyPrefixConst for ProposeDecryptionShareKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_PROPOSE_DECRYPTION_SHARE;
    type Key = ProposeDecryptionShareKey;
    type Value = PreimageDecryptionShare;
}

/// Preimage decryption shares we received
#[derive(Debug, Encodable, Decodable)]
pub struct AgreedDecryptionShareKey(pub ContractId, pub PeerId);

impl DatabaseKeyPrefixConst for AgreedDecryptionShareKey {
    const DB_PREFIX: u8 = DB_PREFIX_AGREED_DECRYPTION_SHARE;
    type Key = Self;
    type Value = PreimageDecryptionShare;
}

/// Preimage decryption shares we received
#[derive(Debug, Encodable)]
pub struct AgreedDecryptionShareKeyPrefix;

impl DatabaseKeyPrefixConst for AgreedDecryptionShareKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_AGREED_DECRYPTION_SHARE;
    type Key = AgreedDecryptionShareKey;
    type Value = PreimageDecryptionShare;
}

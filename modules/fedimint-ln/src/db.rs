use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable, ModuleRegistry};
use fedimint_api::{OutPoint, PeerId};
use secp256k1::PublicKey;

use crate::contracts::{incoming::IncomingContractOffer, ContractId, PreimageDecryptionShare};
use crate::{ContractAccount, LightningGateway, OutputOutcome};

const DB_PREFIX_CONTRACT: u8 = 0x40;
const DB_PREFIX_OFFER: u8 = 0x41;
const DB_PREFIX_PROPOSE_DECRYPTION_SHARE: u8 = 0x42;
const DB_PREFIX_AGREED_DECRYPTION_SHARE: u8 = 0x43;
const DB_PREFIX_CONTRACT_UPDATE: u8 = 0x44;
const DB_PREFIX_LIGHTNING_GATEWAY: u8 = 0x45;

#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct ContractKey(pub ContractId);

impl DatabaseKeyPrefixConst for ContractKey {
    const DB_PREFIX: u8 = DB_PREFIX_CONTRACT;
    type Key = Self;
    type Value = ContractAccount;
}

#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct ContractKeyPrefix;

impl DatabaseKeyPrefixConst for ContractKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_CONTRACT;
    type Key = ContractKey;
    type Value = ContractAccount;
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

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKey(pub PublicKey);

impl DatabaseKeyPrefixConst for LightningGatewayKey {
    const DB_PREFIX: u8 = DB_PREFIX_LIGHTNING_GATEWAY;
    type Key = Self;
    type Value = LightningGateway;
}

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKeyPrefix;

impl DatabaseKeyPrefixConst for LightningGatewayKeyPrefix {
    const DB_PREFIX: u8 = DB_PREFIX_LIGHTNING_GATEWAY;
    type Key = LightningGatewayKey;
    type Value = LightningGateway;
}

use fedimint_api::db::DatabaseKeyPrefixConst;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::{OutPoint, PeerId};
use secp256k1::PublicKey;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::contracts::{incoming::IncomingContractOffer, ContractId, PreimageDecryptionShare};
use crate::{ContractAccount, LightningGateway, LightningOutputOutcome};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Contract = 0x40,
    Offer = 0x41,
    ProposeDecryptionShare = 0x42,
    AgreedDecryptionShare = 0x43,
    ContractUpdate = 0x44,
    LightningGateway = 0x45,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct ContractKey(pub ContractId);

impl DatabaseKeyPrefixConst for ContractKey {
    const DB_PREFIX: u8 = DbKeyPrefix::Contract as u8;
    type Key = Self;
    type Value = ContractAccount;
}

#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct ContractKeyPrefix;

impl DatabaseKeyPrefixConst for ContractKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::Contract as u8;
    type Key = ContractKey;
    type Value = ContractAccount;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ContractUpdateKey(pub OutPoint);

impl DatabaseKeyPrefixConst for ContractUpdateKey {
    const DB_PREFIX: u8 = DbKeyPrefix::ContractUpdate as u8;
    type Key = Self;
    type Value = LightningOutputOutcome;
}

#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct ContractUpdateKeyPrefix;

impl DatabaseKeyPrefixConst for ContractUpdateKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::ContractUpdate as u8;
    type Key = ContractUpdateKey;
    type Value = LightningOutputOutcome;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OfferKey(pub bitcoin_hashes::sha256::Hash);

impl DatabaseKeyPrefixConst for OfferKey {
    const DB_PREFIX: u8 = DbKeyPrefix::Offer as u8;
    type Key = Self;
    type Value = IncomingContractOffer;
}

#[derive(Debug, Encodable, Decodable)]
pub struct OfferKeyPrefix;

impl DatabaseKeyPrefixConst for OfferKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::Offer as u8;
    type Key = OfferKey;
    type Value = IncomingContractOffer;
}

// TODO: remove redundancy
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ProposeDecryptionShareKey(pub ContractId);

impl DatabaseKeyPrefixConst for ProposeDecryptionShareKey {
    const DB_PREFIX: u8 = DbKeyPrefix::ProposeDecryptionShare as u8;
    type Key = Self;
    type Value = PreimageDecryptionShare;
}

/// Our preimage decryption shares that still need to be broadcasted
#[derive(Debug, Encodable)]
pub struct ProposeDecryptionShareKeyPrefix;

impl DatabaseKeyPrefixConst for ProposeDecryptionShareKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::ProposeDecryptionShare as u8;
    type Key = ProposeDecryptionShareKey;
    type Value = PreimageDecryptionShare;
}

/// Preimage decryption shares we received
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct AgreedDecryptionShareKey(pub ContractId, pub PeerId);

impl DatabaseKeyPrefixConst for AgreedDecryptionShareKey {
    const DB_PREFIX: u8 = DbKeyPrefix::AgreedDecryptionShare as u8;
    type Key = Self;
    type Value = PreimageDecryptionShare;
}

/// Preimage decryption shares we received
#[derive(Debug, Encodable)]
pub struct AgreedDecryptionShareKeyPrefix;

impl DatabaseKeyPrefixConst for AgreedDecryptionShareKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::AgreedDecryptionShare as u8;
    type Key = AgreedDecryptionShareKey;
    type Value = PreimageDecryptionShare;
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LightningGatewayKey(pub PublicKey);

impl DatabaseKeyPrefixConst for LightningGatewayKey {
    const DB_PREFIX: u8 = DbKeyPrefix::LightningGateway as u8;
    type Key = Self;
    type Value = LightningGateway;
}

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKeyPrefix;

impl DatabaseKeyPrefixConst for LightningGatewayKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::LightningGateway as u8;
    type Key = LightningGatewayKey;
    type Value = LightningGateway;
}

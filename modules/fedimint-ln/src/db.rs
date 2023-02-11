use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::impl_db_prefix_const;
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

#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct ContractKeyPrefix;

impl_db_prefix_const!(
    key = ContractKey,
    value = ContractAccount,
    prefix = DbKeyPrefix::Contract,
    key_prefix = ContractKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ContractUpdateKey(pub OutPoint);

#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct ContractUpdateKeyPrefix;

impl_db_prefix_const!(
    key = ContractUpdateKey,
    value = LightningOutputOutcome,
    prefix = DbKeyPrefix::ContractUpdate,
    key_prefix = ContractUpdateKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OfferKey(pub bitcoin_hashes::sha256::Hash);

#[derive(Debug, Encodable, Decodable)]
pub struct OfferKeyPrefix;

impl_db_prefix_const!(
    key = OfferKey,
    value = IncomingContractOffer,
    prefix = DbKeyPrefix::Offer,
    key_prefix = OfferKeyPrefix
);

// TODO: remove redundancy
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ProposeDecryptionShareKey(pub ContractId);

/// Our preimage decryption shares that still need to be broadcasted
#[derive(Debug, Encodable)]
pub struct ProposeDecryptionShareKeyPrefix;

impl_db_prefix_const!(
    key = ProposeDecryptionShareKey,
    value = PreimageDecryptionShare,
    prefix = DbKeyPrefix::ProposeDecryptionShare,
    key_prefix = ProposeDecryptionShareKeyPrefix
);

/// Preimage decryption shares we received
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct AgreedDecryptionShareKey(pub ContractId, pub PeerId);

/// Preimage decryption shares we received
#[derive(Debug, Encodable)]
pub struct AgreedDecryptionShareKeyPrefix;

impl_db_prefix_const!(
    key = AgreedDecryptionShareKey,
    value = PreimageDecryptionShare,
    prefix = DbKeyPrefix::AgreedDecryptionShare,
    key_prefix = AgreedDecryptionShareKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LightningGatewayKey(pub PublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKeyPrefix;

impl_db_prefix_const!(
    key = LightningGatewayKey,
    value = LightningGateway,
    prefix = DbKeyPrefix::LightningGateway,
    key_prefix = LightningGatewayKeyPrefix
);

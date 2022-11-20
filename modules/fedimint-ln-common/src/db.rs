use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, OutPoint, PeerId};
use secp256k1::PublicKey;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::contracts::incoming::IncomingContractOffer;
use crate::contracts::{ContractId, PreimageDecryptionShare};
use crate::{ContractAccount, LightningGateway, LightningOutputOutcome, RoundConsensus};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Contract = 0x40,
    Offer = 0x41,
    ProposeDecryptionShare = 0x42,
    AgreedDecryptionShare = 0x43,
    ContractUpdate = 0x44,
    LightningGateway = 0x45,
    RoundConsensus = 0x46,
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

impl_db_record!(
    key = ContractKey,
    value = ContractAccount,
    db_prefix = DbKeyPrefix::Contract,
);
impl_db_lookup!(key = ContractKey, query_prefix = ContractKeyPrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ContractUpdateKey(pub OutPoint);

#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct ContractUpdateKeyPrefix;

impl_db_record!(
    key = ContractUpdateKey,
    value = LightningOutputOutcome,
    db_prefix = DbKeyPrefix::ContractUpdate,
);
impl_db_lookup!(
    key = ContractUpdateKey,
    query_prefix = ContractUpdateKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OfferKey(pub bitcoin_hashes::sha256::Hash);

#[derive(Debug, Encodable, Decodable)]
pub struct OfferKeyPrefix;

impl_db_record!(
    key = OfferKey,
    value = IncomingContractOffer,
    db_prefix = DbKeyPrefix::Offer,
);
impl_db_lookup!(key = OfferKey, query_prefix = OfferKeyPrefix);

// TODO: remove redundancy
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ProposeDecryptionShareKey(pub ContractId);

/// Our preimage decryption shares that still need to be broadcasted
#[derive(Debug, Encodable)]
pub struct ProposeDecryptionShareKeyPrefix;

impl_db_record!(
    key = ProposeDecryptionShareKey,
    value = PreimageDecryptionShare,
    db_prefix = DbKeyPrefix::ProposeDecryptionShare,
);
impl_db_lookup!(
    key = ProposeDecryptionShareKey,
    query_prefix = ProposeDecryptionShareKeyPrefix
);

/// Preimage decryption shares we received
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct AgreedDecryptionShareKey(pub ContractId, pub PeerId);

/// Preimage decryption shares we received
#[derive(Debug, Encodable)]
pub struct AgreedDecryptionShareKeyPrefix;

impl_db_record!(
    key = AgreedDecryptionShareKey,
    value = PreimageDecryptionShare,
    db_prefix = DbKeyPrefix::AgreedDecryptionShare,
);
impl_db_lookup!(
    key = AgreedDecryptionShareKey,
    query_prefix = AgreedDecryptionShareKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LightningGatewayKey(pub PublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKeyPrefix;

impl_db_record!(
    key = LightningGatewayKey,
    value = LightningGateway,
    db_prefix = DbKeyPrefix::LightningGateway,
);
impl_db_lookup!(
    key = LightningGatewayKey,
    query_prefix = LightningGatewayKeyPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct RoundConsensusKey;

impl_db_record!(
    key = RoundConsensusKey,
    value = RoundConsensus,
    db_prefix = DbKeyPrefix::RoundConsensus,
);

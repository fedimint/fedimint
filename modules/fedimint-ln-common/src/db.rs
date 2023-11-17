use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, Amount, OutPoint, PeerId};
use secp256k1::PublicKey;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::contracts::incoming::IncomingContractOffer;
use crate::contracts::{ContractId, FundedContract, IdentifiableContract, PreimageDecryptionShare};
use crate::{ContractAccount, LightningGatewayRegistration, LightningOutputOutcomeV0};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Contract = 0x40,
    Offer = 0x41,
    ProposeDecryptionShare = 0x42,
    AgreedDecryptionShare = 0x43,
    ContractUpdate = 0x44,
    LightningGateway = 0x45,
    BlockCountVote = 0x46,
    EncryptedPreimageIndex = 0x47,
    LightningAuditItem = 0x48,
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
    notify_on_modify = true,
);
impl_db_lookup!(key = ContractKey, query_prefix = ContractKeyPrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ContractUpdateKey(pub OutPoint);

#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct ContractUpdateKeyPrefix;

impl_db_record!(
    key = ContractUpdateKey,
    value = LightningOutputOutcomeV0,
    db_prefix = DbKeyPrefix::ContractUpdate,
);
impl_db_lookup!(
    key = ContractUpdateKey,
    query_prefix = ContractUpdateKeyPrefix
);

/// We keep a separate mapping of incoming and outgoing ContractIds to Amounts,
/// which allows us to quickly audit the total liabilities in the Lightning
/// module.
///
/// This differs from MintAuditItemKeys, since it doesn't include an aggregate
/// *Total key. The motivation for not including the aggregate key is how the
/// Amount associated to the contract mutates in the LN module. When a contract
/// reaches a terminal state, the associated amount updates to 0. The additional
/// complexity to update both the individual incoming/outgoing contract audit
/// keys along with the aggregate audit key is not necessary.
///
/// In contrast to the mint module, the total number of LN audit keys with a
/// non-zero amount will not grow linearly, so querying the LN audit keys with a
/// non-zero amount should remain quick.
#[derive(Debug, Clone, Encodable, Decodable, Serialize, PartialEq)]
pub enum LightningAuditItemKey {
    Incoming(ContractId),
    Outgoing(ContractId),
}

impl LightningAuditItemKey {
    pub fn from_funded_contract(contract: &FundedContract) -> Self {
        match contract {
            FundedContract::Outgoing(outgoing) => {
                LightningAuditItemKey::Outgoing(outgoing.contract_id())
            }
            FundedContract::Incoming(incoming) => {
                LightningAuditItemKey::Incoming(incoming.contract.contract_id())
            }
        }
    }
}

#[derive(Debug, Encodable, Decodable)]
pub struct LightningAuditItemKeyPrefix;

impl_db_record!(
    key = LightningAuditItemKey,
    value = Amount,
    db_prefix = DbKeyPrefix::LightningAuditItem,
);
impl_db_lookup!(
    key = LightningAuditItemKey,
    query_prefix = LightningAuditItemKeyPrefix
);

/// We save the hash of the encrypted preimage from each accepted offer so that
/// we can make sure that no preimage is used twice.
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct EncryptedPreimageIndexKey(pub bitcoin_hashes::sha256::Hash);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct EncryptedPreimageIndexKeyPrefix;

impl_db_record!(
    key = EncryptedPreimageIndexKey,
    value = (),
    db_prefix = DbKeyPrefix::EncryptedPreimageIndex,
);
impl_db_lookup!(
    key = EncryptedPreimageIndexKey,
    query_prefix = EncryptedPreimageIndexKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OfferKey(pub bitcoin_hashes::sha256::Hash);

#[derive(Debug, Encodable, Decodable)]
pub struct OfferKeyPrefix;

impl_db_record!(
    key = OfferKey,
    value = IncomingContractOffer,
    db_prefix = DbKeyPrefix::Offer,
    notify_on_modify = true,
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

#[derive(Debug, Encodable)]
pub struct AgreedDecryptionShareContractIdPrefix(pub ContractId);

impl_db_record!(
    key = AgreedDecryptionShareKey,
    value = PreimageDecryptionShare,
    db_prefix = DbKeyPrefix::AgreedDecryptionShare,
);
impl_db_lookup!(
    key = AgreedDecryptionShareKey,
    query_prefix = AgreedDecryptionShareKeyPrefix,
    query_prefix = AgreedDecryptionShareContractIdPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LightningGatewayKey(pub PublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKeyPrefix;

impl_db_record!(
    key = LightningGatewayKey,
    value = LightningGatewayRegistration,
    db_prefix = DbKeyPrefix::LightningGateway,
);
impl_db_lookup!(
    key = LightningGatewayKey,
    query_prefix = LightningGatewayKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct BlockCountVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockCountVotePrefix;

impl_db_record!(
    key = BlockCountVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::BlockCountVote
);

impl_db_lookup!(key = BlockCountVoteKey, query_prefix = BlockCountVotePrefix);

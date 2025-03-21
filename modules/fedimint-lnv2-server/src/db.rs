use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::util::SafeUrl;
use fedimint_core::{PeerId, impl_db_lookup, impl_db_record};
use fedimint_lnv2_common::ContractId;
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract};
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;
use tpe::DecryptionKeyShare;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    BlockCountVote = 0x41,
    UnixTimeVote = 0x42,
    IncomingContract = 0x43,
    OutgoingContract = 0x44,
    DecryptionKeyShare = 0x45,
    Preimage = 0x46,
    Gateway = 0x47,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct BlockCountVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockCountVotePrefix;

impl_db_record!(
    key = BlockCountVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::BlockCountVote,
);

impl_db_lookup!(key = BlockCountVoteKey, query_prefix = BlockCountVotePrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct UnixTimeVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnixTimeVotePrefix;

impl_db_record!(
    key = UnixTimeVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::UnixTimeVote,
);

impl_db_lookup!(key = UnixTimeVoteKey, query_prefix = UnixTimeVotePrefix);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct IncomingContractKey(pub ContractId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct IncomingContractPrefix;

impl_db_record!(
    key = IncomingContractKey,
    value = IncomingContract,
    db_prefix = DbKeyPrefix::IncomingContract,
    notify_on_modify = true
);

impl_db_lookup!(
    key = IncomingContractKey,
    query_prefix = IncomingContractPrefix
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct OutgoingContractKey(pub ContractId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct OutgoingContractPrefix;

impl_db_record!(
    key = OutgoingContractKey,
    value = OutgoingContract,
    db_prefix = DbKeyPrefix::OutgoingContract,
    notify_on_modify = true
);

impl_db_lookup!(
    key = OutgoingContractKey,
    query_prefix = OutgoingContractPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct DecryptionKeyShareKey(pub ContractId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct DecryptionKeySharePrefix;

impl_db_record!(
    key = DecryptionKeyShareKey,
    value = DecryptionKeyShare,
    db_prefix = DbKeyPrefix::DecryptionKeyShare,
    notify_on_modify = true
);

impl_db_lookup!(
    key = DecryptionKeyShareKey,
    query_prefix = DecryptionKeySharePrefix
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct PreimageKey(pub ContractId);

#[derive(Debug, Encodable, Decodable)]
pub struct PreimagePrefix;

impl_db_record!(
    key = PreimageKey,
    value = [u8; 32],
    db_prefix = DbKeyPrefix::Preimage,
    notify_on_modify = true
);

impl_db_lookup!(key = PreimageKey, query_prefix = PreimagePrefix);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct GatewayKey(pub SafeUrl);

#[derive(Debug, Encodable, Decodable)]
pub struct GatewayPrefix;

impl_db_record!(
    key = GatewayKey,
    value = (),
    db_prefix = DbKeyPrefix::Gateway,
);

impl_db_lookup!(key = GatewayKey, query_prefix = GatewayPrefix);

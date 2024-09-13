use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::util::SafeUrl;
use fedimint_core::{impl_db_lookup, impl_db_record, OutPoint, PeerId};
use fedimint_lnv2_common::contracts::{IncomingContract, OutgoingContract};
use fedimint_lnv2_common::{ContractId, LightningOutputOutcome};
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    BlockHeightVote = 0x1,
    UnixTimeVote = 0x2,
    IncomingContract = 0x3,
    OutgoingContract = 0x4,
    OutputOutcome = 0x5,
    Preimage = 0x6,
    Gateway = 0x7,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct BlockHeightVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockHeightVotePrefix;

impl_db_record!(
    key = BlockHeightVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::BlockHeightVote,
);

impl_db_lookup!(
    key = BlockHeightVoteKey,
    query_prefix = BlockHeightVotePrefix
);

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
pub struct OutputOutcomeKey(pub OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct LightningOutputOutcomePrefix;

impl_db_record!(
    key = OutputOutcomeKey,
    value = LightningOutputOutcome,
    db_prefix = DbKeyPrefix::OutputOutcome
);

impl_db_lookup!(
    key = OutputOutcomeKey,
    query_prefix = LightningOutputOutcomePrefix
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

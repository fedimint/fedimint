use bitcoin_hashes::sha256;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, OutPoint, PeerId};
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::contracts::{IncomingContract, OutgoingContract};
use crate::LightningOutputOutcome;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    BlockCountVote = 0x45,
    UnixTimeVote = 0x46,
    IncomingContract = 0x47,
    OutgoingContract = 0x48,
    OutputOutcome = 0x49,
    Preimage = 0x50,
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
pub struct IncomingContractKey(pub sha256::Hash);

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
pub struct OutgoingContractKey(pub sha256::Hash);

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

impl OutgoingContractKey {
    pub fn preimage_key(&self) -> PreimageKey {
        PreimageKey(self.0)
    }
}

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

#[derive(Debug, Encodable, Decodable, Serialize, Deserialize)]
pub struct PreimageKey(pub sha256::Hash);

#[derive(Debug, Encodable, Decodable)]
pub struct PreimagePrefix;

impl_db_record!(
    key = PreimageKey,
    value = [u8; 32],
    db_prefix = DbKeyPrefix::Preimage,
    notify_on_modify = true
);

impl_db_lookup!(key = PreimageKey, query_prefix = PreimagePrefix);

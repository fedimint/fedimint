use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{OutPoint, PeerId, impl_db_lookup, impl_db_record};
use fedimint_escrow_common::{ClaimPool, EscrowContract, EscrowId, EscrowOutputOutcome};
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug, strum_macros::Display)]
pub enum DbKeyPrefix {
    EscrowContract = 0x01,
    ClaimPool = 0x02,
    UnixTimeVote = 0x03,
    OutputOutcome = 0x04,
    ContractByKey = 0x05,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ClaimPoolKey(pub EscrowId);

#[derive(Debug, Encodable, Decodable)]
pub struct ClaimPoolPrefix;

impl_db_record!(
    key = ClaimPoolKey,
    value = ClaimPool,
    db_prefix = DbKeyPrefix::ClaimPool
);

impl_db_lookup!(key = ClaimPoolKey, query_prefix = ClaimPoolPrefix);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct EscrowContractKey(pub EscrowId);

#[derive(Debug, Encodable, Decodable)]
pub struct EscrowContractPrefix;

impl_db_record!(
    key = EscrowContractKey,
    value = EscrowContract,
    db_prefix = DbKeyPrefix::EscrowContract
);

impl_db_lookup!(key = EscrowContractKey, query_prefix = EscrowContractPrefix);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct UnixTimeVoteKey(pub PeerId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct UnixTimeVotePrefix;

impl_db_record!(
    key = UnixTimeVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::UnixTimeVote
);

impl_db_lookup!(key = UnixTimeVoteKey, query_prefix = UnixTimeVotePrefix);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct ContractByKeyKey {
    pub key: [u8; 32],
    pub escrow_id: EscrowId,
}

#[allow(dead_code)]
#[derive(Debug, Encodable, Decodable)]
pub struct ContractByKeyPrefix {
    pub key: [u8; 32],
}

impl_db_record!(
    key = ContractByKeyKey,
    value = (),
    db_prefix = DbKeyPrefix::ContractByKey
);
impl_db_lookup!(key = ContractByKeyKey, query_prefix = ContractByKeyPrefix);

#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct EscrowOutputOutcomeKey(pub OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct EscrowOutputOutcomePrefix;

impl_db_record!(
    key = EscrowOutputOutcomeKey,
    value = EscrowOutputOutcome,
    db_prefix = DbKeyPrefix::OutputOutcome,
);

impl_db_lookup!(
    key = EscrowOutputOutcomeKey,
    query_prefix = EscrowOutputOutcomePrefix
);

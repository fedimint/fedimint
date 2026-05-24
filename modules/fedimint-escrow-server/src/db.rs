use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{OutPoint, impl_db_lookup, impl_db_record};
use fedimint_escrow_common::{EscrowContract, EscrowId, EscrowOutputOutcome};
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug, strum_macros::Display)]
pub enum DbKeyPrefix {
    EscrowContract = 0x01,
    OutputOutcome = 0x04
}

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

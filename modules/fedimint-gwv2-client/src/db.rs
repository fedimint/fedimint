use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{OutPoint, impl_db_record};
use fedimint_lnv2_common::contracts::LightningContract;
use strum::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    OutpointContract = 0x43,
    #[allow(dead_code)]
    /// Prefixes between 0xb0..=0xcf shall all be considered allocated for
    /// historical and future external use
    ExternalReservedStart = 0xb0,
    #[allow(dead_code)]
    /// Prefixes between 0xd0..=0xff shall all be considered allocated for
    /// historical and future internal use
    CoreInternalReservedStart = 0xd0,
    #[allow(dead_code)]
    CoreInternalReservedEnd = 0xff,
}

#[derive(Debug, Encodable, Decodable)]
pub struct OutpointContractKey(pub OutPoint);

impl_db_record!(
    key = OutpointContractKey,
    value = LightningContract,
    db_prefix = DbKeyPrefix::OutpointContract,
);

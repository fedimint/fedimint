use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;
use strum::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    // DEPRECATED: was the (PublicKey -> SafeUrl) gateway cache prefix; the
    // cache moved in-memory and is no longer persisted. Do not reuse 0x41
    // for a new variant unless old client databases have been migrated.
    #[allow(dead_code)]
    Gateway = 0x41,
    IncomingContractStreamIndex = 0x42,
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
pub struct IncomingContractStreamIndexKey;

impl_db_record!(
    key = IncomingContractStreamIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::IncomingContractStreamIndex
);

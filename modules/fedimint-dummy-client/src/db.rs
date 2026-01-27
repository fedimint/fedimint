use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, Debug, EnumIter)]
pub enum DbKeyPrefix {
    // Used to verify that 0x50 key can be written to, which used to conflict with
    // `DatabaseVersionKeyV0`
    ClientName = 0x50,
    /// Prefixes between 0xb0..=0xcf shall all be considered allocated for
    /// historical and future external use
    ExternalReservedStart = 0xb0,
    /// Prefixes between 0xd0..=0xff shall all be considered allocated for
    /// historical and future internal use
    CoreInternalReservedStart = 0xd0,
    /// Prefixes between 0xd0..=0xff shall all be considered allocated for
    /// historical and future internal use
    CoreInternalReservedEnd = 0xff,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DummyClientNameKey;

impl_db_record!(
    key = DummyClientNameKey,
    value = String,
    db_prefix = DbKeyPrefix::ClientName,
);

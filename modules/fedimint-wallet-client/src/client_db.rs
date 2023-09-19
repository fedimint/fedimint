use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;
use serde::Serialize;
use strum_macros::EnumIter;

#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    NextPegInTweakIndex = 0x2c,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub(crate) struct NextPegInTweakIndexKey;

impl_db_record!(
    key = NextPegInTweakIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::NextPegInTweakIndex,
);

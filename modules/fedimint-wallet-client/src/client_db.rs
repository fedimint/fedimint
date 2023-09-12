use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;
use serde::Serialize;

enum DbKeyPrefix {
    NextPegInTweakIndex = 0x2c,
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub(crate) struct NextPegInTweakIndexKey;

impl_db_record!(
    key = NextPegInTweakIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::NextPegInTweakIndex,
);

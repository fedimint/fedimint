use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::MetaFields;

#[repr(u8)]
#[derive(Clone, Debug, EnumIter)]
pub enum DbKeyPrefix {
    LegacyMetaOverrideCache = 0x00,
    MetaCache = 0x01,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LegacyMetaOverrideCacheKey;

impl_db_record!(
    key = LegacyMetaOverrideCacheKey,
    value = MetaFields,
    db_prefix = DbKeyPrefix::LegacyMetaOverrideCache,
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct MetaCacheKey;

impl_db_record!(
    key = MetaCacheKey,
    value = MetaFields,
    db_prefix = DbKeyPrefix::MetaCache,
);

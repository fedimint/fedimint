use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, impl_db_record};
use serde::Serialize;
use strum_macros::EnumIter;

/// Namespaces DB keys for this module
#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    /// Tracks the federation's assets for audit purposes
    Assets = 0x03,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Single key to track the federation's total assets
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct DummyAssetsKey;

impl_db_record!(
    key = DummyAssetsKey,
    value = Amount,
    db_prefix = DbKeyPrefix::Assets,
);

/// Prefix for iterating over assets (used for audit)
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct DummyAssetsPrefix;

fedimint_core::impl_db_lookup!(key = DummyAssetsKey, query_prefix = DummyAssetsPrefix,);

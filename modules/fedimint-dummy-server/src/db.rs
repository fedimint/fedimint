use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, InPoint, OutPoint, impl_db_lookup, impl_db_record};
use serde::Serialize;
use strum_macros::EnumIter;

/// Namespaces DB keys for this module
#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    InputAudit = 0x01,
    OutputAudit = 0x02,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Tracks inputs for audit (assets)
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct DummyInputAuditKey(pub InPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct DummyInputAuditPrefix;

impl_db_record!(
    key = DummyInputAuditKey,
    value = Amount,
    db_prefix = DbKeyPrefix::InputAudit,
);
impl_db_lookup!(
    key = DummyInputAuditKey,
    query_prefix = DummyInputAuditPrefix
);

/// Tracks outputs for audit (liabilities)
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct DummyOutputAuditKey(pub OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct DummyOutputAuditPrefix;

impl_db_record!(
    key = DummyOutputAuditKey,
    value = Amount,
    db_prefix = DbKeyPrefix::OutputAudit,
);
impl_db_lookup!(
    key = DummyOutputAuditKey,
    query_prefix = DummyOutputAuditPrefix
);

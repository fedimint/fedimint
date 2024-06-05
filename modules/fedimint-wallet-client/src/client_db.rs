use std::time::SystemTime;

use bitcoin::OutPoint;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use serde::Serialize;
use strum_macros::EnumIter;

#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    NextPegInTweakIndex = 0x2c,
    PegInTweakIndex = 0x2d,
    ClaimedPegIn = 0x2e,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A counter tracking next index to use to derive a peg-in address
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct NextPegInTweakIndexKey;

impl_db_record!(
    key = NextPegInTweakIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::NextPegInTweakIndex,
);

/// Peg in index that was already allocated and is being tracked for deposits to
/// claim
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegInTweakIndexKey(u64);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegInTweakIndexPrefix;

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegInTweakIndexData {
    crated_at: SystemTime,
    next_check_time: Option<SystemTime>,
}

impl_db_record!(
    key = PegInTweakIndexKey,
    value = PegInTweakIndexData,
    db_prefix = DbKeyPrefix::PegInTweakIndex,
);

impl_db_lookup!(
    key = PegInTweakIndexKey,
    query_prefix = PegInTweakIndexPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct ClaimedPegInKey {
    peg_in_index: u64,
    btc_out_point: OutPoint,
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct ClaimedPegInPrefix;

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct ClaimedPegInData {}

impl_db_record!(
    key = ClaimedPegInKey,
    value = ClaimedPegInData,
    db_prefix = DbKeyPrefix::ClaimedPegIn,
);
impl_db_lookup!(key = ClaimedPegInKey, query_prefix = ClaimedPegInPrefix);

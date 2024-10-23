use core::fmt;
use std::ops;
use std::time::SystemTime;

use fedimint_client::module::init::recovery::RecoveryFromHistoryCommon;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, TransactionId};
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::backup::WalletRecoveryState;

#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    NextPegInTweakIndex = 0x2c,
    PegInTweakIndex = 0x2d,
    ClaimedPegIn = 0x2e,
    RecoveryFinalized = 0x2f,
    RecoveryState = 0x30,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// An index of a deposit address
///
/// Under the hood it's similar to `ChildId`, but in a wallet module
/// it's used often enough to deserve own newtype.
#[derive(
    Copy,
    Clone,
    Debug,
    Encodable,
    Decodable,
    Serialize,
    Deserialize,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct TweakIdx(pub u64);

impl fmt::Display for TweakIdx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("TweakIdx({})", self.0))
    }
}

impl TweakIdx {
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }

    #[must_use]
    pub fn prev(self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }

    #[must_use]
    pub fn advance(self, i: u64) -> Self {
        Self(self.0 + i)
    }

    pub fn saturating_sub(&self, rhs: TweakIdx) -> u64 {
        self.0.saturating_sub(rhs.0)
    }
}

impl ops::Sub for TweakIdx {
    type Output = u64;

    fn sub(self, rhs: Self) -> Self::Output {
        self.0 - rhs.0
    }
}

/// A counter tracking next index to use to derive a peg-in address
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct NextPegInTweakIndexKey;

impl_db_record!(
    key = NextPegInTweakIndexKey,
    value = TweakIdx,
    db_prefix = DbKeyPrefix::NextPegInTweakIndex,
);

/// Peg in index that was already allocated and is being tracked for deposits to
/// claim
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegInTweakIndexKey(pub TweakIdx);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegInTweakIndexPrefix;

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegInTweakIndexData {
    pub operation_id: OperationId,
    pub creation_time: SystemTime,
    pub last_check_time: Option<SystemTime>,
    pub next_check_time: Option<SystemTime>,
    pub claimed: Vec<bitcoin30::OutPoint>,
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
    pub peg_in_index: TweakIdx,
    pub btc_out_point: bitcoin30::OutPoint,
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct ClaimedPegInPrefix;

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct ClaimedPegInData {
    pub claim_txid: TransactionId,
    pub change: Vec<fedimint_core::OutPoint>,
}

impl_db_record!(
    key = ClaimedPegInKey,
    value = ClaimedPegInData,
    db_prefix = DbKeyPrefix::ClaimedPegIn,
    notify_on_modify = true,
);
impl_db_lookup!(key = ClaimedPegInKey, query_prefix = ClaimedPegInPrefix);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct RecoveryFinalizedKey;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RecoveryFinalizedKeyPrefix;

impl_db_record!(
    key = RecoveryFinalizedKey,
    value = bool,
    db_prefix = DbKeyPrefix::RecoveryFinalized,
);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct RecoveryStateKey;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct RestoreStateKeyPrefix;

impl_db_record!(
    key = RecoveryStateKey,
    value = (WalletRecoveryState, RecoveryFromHistoryCommon),
    db_prefix = DbKeyPrefix::RecoveryState,
);

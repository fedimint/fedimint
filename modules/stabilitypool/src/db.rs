use std::fmt::Debug;

use fedimint_api::{
    db::{DatabaseKeyPrefixConst, DatabaseTransaction},
    encoding::{Decodable, Encodable},
};
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::{action::ActionStaged, epoch::EpochOutcome, AccountBalance, EpochEnd};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    /// Account entry prefix.
    ///   Key: x-only-pubkey (represents the account)
    /// Value: account balances + pool side
    Account = 0xE0,

    /// Successful deposit outcome entry prefix.
    ///   Key: tx outpoint
    /// Value: x-only-pubkey (represents the account where funds are deposited)
    DepositOutcome,

    /// Where we store epoch outcome.
    ///   Key: epoch_id
    /// Value: EpochOutcome
    EpochOutcome,

    /// Epoch consensus state information.
    ///   Key: ~,
    /// Value: epoch_id
    LastEpochEnded,
    LastEpochSettled,

    /// The last valid `epoch_end` item we got from given peer (Consensus Item).
    ///   Key: PeerId
    /// Value: EpochEnd
    EpochEnd,

    /// User action staged for the next epoch (Consensus Item)
    ///   Key: x-only-pubkey (account id)
    /// Value: action::ActionStaged
    ActionStaged,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct AccountBalanceKey(pub secp256k1_zkp::XOnlyPublicKey);

impl DatabaseKeyPrefixConst for AccountBalanceKey {
    const DB_PREFIX: u8 = DbKeyPrefix::Account as _;
    type Key = Self;
    type Value = AccountBalance;
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct AccountBalanceKeyPrefix;

impl DatabaseKeyPrefixConst for AccountBalanceKeyPrefix {
    const DB_PREFIX: u8 = <AccountBalanceKey as DatabaseKeyPrefixConst>::DB_PREFIX;
    type Key = <AccountBalanceKey as DatabaseKeyPrefixConst>::Key;
    type Value = <AccountBalanceKey as DatabaseKeyPrefixConst>::Value;
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct DepositOutcomeKey(pub fedimint_api::OutPoint);

impl DatabaseKeyPrefixConst for DepositOutcomeKey {
    const DB_PREFIX: u8 = DbKeyPrefix::DepositOutcome as _;
    type Key = Self;
    type Value = secp256k1_zkp::XOnlyPublicKey;
}

#[derive(
    Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize, Ord, PartialOrd,
)]
pub struct EpochOutcomeKey(pub u64);

impl DatabaseKeyPrefixConst for EpochOutcomeKey {
    const DB_PREFIX: u8 = DbKeyPrefix::EpochOutcome as _;
    type Key = Self;
    type Value = EpochOutcome;
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct EpochOutcomeKeyPrefix;

impl DatabaseKeyPrefixConst for EpochOutcomeKeyPrefix {
    const DB_PREFIX: u8 = <EpochOutcomeKey as DatabaseKeyPrefixConst>::DB_PREFIX;
    type Key = <EpochOutcomeKey as DatabaseKeyPrefixConst>::Key;
    type Value = <EpochOutcomeKey as DatabaseKeyPrefixConst>::Value;
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct LastEpochEndedKey;

impl DatabaseKeyPrefixConst for LastEpochEndedKey {
    const DB_PREFIX: u8 = DbKeyPrefix::LastEpochEnded as _;
    type Key = Self;
    type Value = u64;
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct LastEpochSettledKey;

impl DatabaseKeyPrefixConst for LastEpochSettledKey {
    const DB_PREFIX: u8 = DbKeyPrefix::LastEpochSettled as _;
    type Key = Self;
    type Value = u64;
}

#[derive(
    Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize, Ord, PartialOrd,
)]
pub struct EpochEndKey(pub fedimint_api::PeerId);

impl DatabaseKeyPrefixConst for EpochEndKey {
    const DB_PREFIX: u8 = DbKeyPrefix::EpochEnd as _;
    type Key = Self;
    type Value = EpochEnd;
}

#[derive(
    Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize, Ord, PartialOrd,
)]
pub struct EpochEndKeyPrefix;

impl DatabaseKeyPrefixConst for EpochEndKeyPrefix {
    const DB_PREFIX: u8 = <EpochEndKey as DatabaseKeyPrefixConst>::DB_PREFIX;
    type Key = <EpochEndKey as DatabaseKeyPrefixConst>::Key;
    type Value = <EpochEndKey as DatabaseKeyPrefixConst>::Value;
}

#[derive(
    Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize, Ord, PartialOrd,
)]
pub struct ActionStagedKey(pub secp256k1_zkp::XOnlyPublicKey);

impl DatabaseKeyPrefixConst for ActionStagedKey {
    const DB_PREFIX: u8 = DbKeyPrefix::ActionStaged as _;
    type Key = Self;
    type Value = ActionStaged;
}

#[derive(
    Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize, Deserialize, Ord, PartialOrd,
)]
pub struct ActionStagedKeyPrefix;

impl DatabaseKeyPrefixConst for ActionStagedKeyPrefix {
    const DB_PREFIX: u8 = <ActionStagedKey as DatabaseKeyPrefixConst>::DB_PREFIX;
    type Key = <ActionStagedKey as DatabaseKeyPrefixConst>::Key;
    type Value = <ActionStagedKey as DatabaseKeyPrefixConst>::Value;
}

pub async fn get<K, V>(dbtx: &mut DatabaseTransaction<'_>, key: &K) -> Option<V>
where
    K: Encodable + Decodable + Debug + DatabaseKeyPrefixConst<Value = V>,
{
    dbtx.get_value(key).await.expect("db error")
}

pub async fn set<K, V>(dbtx: &mut DatabaseTransaction<'_>, key: &K, value: &V) -> Option<V>
where
    K: Encodable + Decodable + Debug + DatabaseKeyPrefixConst<Value = V>,
{
    dbtx.insert_entry(key, value).await.expect("db error")
}

pub async fn pop<K, V>(dbtx: &mut DatabaseTransaction<'_>, key: &K) -> Option<V>
where
    K: Encodable + Decodable + Debug + DatabaseKeyPrefixConst<Value = V>,
{
    dbtx.remove_entry(key).await.expect("db error")
}

pub async fn prefix_remove_all<'a, P>(dbtx: &mut DatabaseTransaction<'_>, key_prefix: &'a P)
where
    P: Encodable + Debug + DatabaseKeyPrefixConst,
{
    dbtx.remove_by_prefix(key_prefix).await.expect("db error")
}

pub async fn prefix_values<'a, P, V>(
    dbtx: &'a mut DatabaseTransaction<'_>,
    key_prefix: &'a P,
) -> impl Iterator<Item = V> + 'a
where
    P: Encodable + Debug + DatabaseKeyPrefixConst<Value = V>,
{
    dbtx.find_by_prefix(key_prefix)
        .await
        .map(|res| res.expect("db error").1)
}

pub async fn prefix_entries<'a, P, K, V>(
    dbtx: &'a mut DatabaseTransaction<'_>,
    key_prefix: &'a P,
) -> impl Iterator<Item = (K, V)> + 'a
where
    P: Encodable + Debug + DatabaseKeyPrefixConst<Key = K, Value = V>,
    K: 'a,
    V: 'a,
{
    dbtx.find_by_prefix(key_prefix)
        .await
        .map(Result::unwrap)
        .map(|(k, v)| (k, v))
}

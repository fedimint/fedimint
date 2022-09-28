use fedimint_api::Amount;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::iter::FromIterator;
use tbs::{PublicKeyShare, SecretKeyShare};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct InvalidAmountTierError(pub Amount);

impl std::fmt::Display for InvalidAmountTierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Amount tier unknown to mint: {}", self.0)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Tiered<T>(BTreeMap<Amount, T>);

impl<T> Tiered<T> {
    pub fn structural_eq<O>(&self, other: &Tiered<O>) -> bool {
        self.0.keys().eq(other.0.keys())
    }

    /// Returns a reference to the key of the specified tier
    pub fn tier(&self, amount: &Amount) -> Result<&T, InvalidAmountTierError> {
        self.0.get(amount).ok_or(InvalidAmountTierError(*amount))
    }

    pub fn tiers(&self) -> impl DoubleEndedIterator<Item = &Amount> {
        self.0.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Amount, &T)> {
        self.0.iter().map(|(amt, key)| (*amt, key))
    }

    pub fn get(&self, amt: Amount) -> Option<&T> {
        self.0.get(&amt)
    }

    pub fn as_map(&self) -> &BTreeMap<Amount, T> {
        &self.0
    }
}

impl Tiered<SecretKeyShare> {
    pub fn to_public(&self) -> Tiered<PublicKeyShare> {
        Tiered(
            self.iter()
                .map(|(amt, key)| (amt, key.to_pub_key_share()))
                .collect(),
        )
    }
}

impl<T> FromIterator<(Amount, T)> for Tiered<T> {
    fn from_iter<I: IntoIterator<Item = (Amount, T)>>(iter: I) -> Self {
        Tiered(iter.into_iter().collect())
    }
}

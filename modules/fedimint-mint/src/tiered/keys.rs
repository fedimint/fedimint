use crate::InvalidAmountTierError;
use fedimint_api::Amount;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::iter::FromIterator;
use tbs::{PublicKeyShare, SecretKeyShare};

/// Represents all tiered keys belonging to a certain entity
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Keys<K> {
    pub keys: BTreeMap<Amount, K>,
}

impl<K> Keys<K> {
    pub fn structural_eq<O>(&self, other: &Keys<O>) -> bool {
        self.keys.keys().eq(other.keys.keys())
    }

    /// Returns a reference to the key of the specified tier
    pub fn tier(&self, amount: &Amount) -> Result<&K, InvalidAmountTierError> {
        self.keys.get(amount).ok_or(InvalidAmountTierError(*amount))
    }

    pub fn tiers(&self) -> impl Iterator<Item = &Amount> {
        self.keys.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Amount, &K)> {
        self.keys.iter().map(|(amt, key)| (*amt, key))
    }
}

impl Keys<SecretKeyShare> {
    pub fn to_public(&self) -> Keys<PublicKeyShare> {
        Keys {
            keys: self
                .keys
                .iter()
                .map(|(amt, key)| (*amt, key.to_pub_key_share()))
                .collect(),
        }
    }
}

impl<K> FromIterator<(Amount, K)> for Keys<K> {
    fn from_iter<T: IntoIterator<Item = (Amount, K)>>(iter: T) -> Self {
        Keys {
            keys: iter.into_iter().collect(),
        }
    }
}

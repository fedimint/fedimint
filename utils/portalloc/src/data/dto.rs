use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RangeData {
    size: u16,
    /// local time unix timestamp
    expires: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RootData {
    pub keys: BTreeMap<u16, RangeData>,
}

impl RootData {
    pub fn reclaim(self, now: u64) -> Self {
        Self {
            keys: self
                .keys
                .into_iter()
                .filter(|(_k, v)| now < v.expires)
                .collect(),
        }
    }

    pub fn contains(&self, range: &std::ops::Range<u16>) -> bool {
        self.keys.iter().any(|(k, v)| {
            let start = *k;
            let end = start + v.size;

            start < range.end && range.start < end
        })
    }

    pub fn insert(&mut self, range: std::ops::Range<u16>, now_ts: u64) {
        assert!(!self.contains(&range));
        self.keys.insert(
            range.start,
            RangeData {
                size: range.len() as u16,
                expires: now_ts,
            },
        );
    }
}

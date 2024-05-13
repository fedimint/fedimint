use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RangeData {
    size: u16,
    /// local time unix timestamp
    expires: u64,
}

fn default_next() -> u16 {
    crate::LOW
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RootData {
    #[serde(default = "default_next")]
    pub next: u16,
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
            ..self
        }
    }

    /// Check if `range` conflicts with anything already reserved
    ///
    /// If it does return next address after the range that conflicted.
    pub fn contains(&self, range: &std::ops::Range<u16>) -> Option<u16> {
        self.keys
            .iter()
            .find(|(k, v)| {
                let start = **k;
                let end = start + v.size;

                start < range.end && range.start < end
            })
            .map(|(k, v)| k + v.size)
    }

    pub fn insert(&mut self, range: std::ops::Range<u16>, now_ts: u64) {
        assert!(self.contains(&range).is_none());
        self.keys.insert(
            range.start,
            RangeData {
                size: range.len() as u16,
                expires: now_ts,
            },
        );
        self.next = range.end;
    }
}

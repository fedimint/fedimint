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
    pub fn contains(&self, range: std::ops::Range<u16>) -> Option<u16> {
        self.keys.range(..range.end).next_back().and_then(|(k, v)| {
            let start = *k;
            let end = start + v.size;

            if start < range.end && range.start < end {
                Some(end)
            } else {
                None
            }
        })
    }

    pub fn insert(&mut self, range: std::ops::Range<u16>, now_ts: u64) {
        assert!(self.contains(range.clone()).is_none());
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

#[test]
fn root_data_sanity() {
    let mut r = RootData::default();

    r.insert(2..4, 0);
    r.insert(6..8, 0);
    r.insert(100..108, 0);
    assert_eq!(r.contains(0..2), None);
    assert_eq!(r.contains(0..3), Some(4));
    assert_eq!(r.contains(2..4), Some(4));
    assert_eq!(r.contains(3..4), Some(4));
    assert_eq!(r.contains(3..5), Some(4));
    assert_eq!(r.contains(4..6), None);
    assert_eq!(r.contains(0..10), Some(8));
    assert_eq!(r.contains(6..10), Some(8));
    assert_eq!(r.contains(7..8), Some(8));
    assert_eq!(r.contains(8..10), None);
}

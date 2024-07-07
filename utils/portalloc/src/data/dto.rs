use std::collections::BTreeMap;
use std::net::TcpListener;

use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};

use crate::{HIGH, LOG_PORT_ALLOC, LOW};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
struct RangeData {
    size: u16,
    /// local time unix timestamp
    expires: u64,
}

type UnixTimestamp = u64;

fn now_ts() -> UnixTimestamp {
    fedimint_core::time::duration_since_epoch().as_secs()
}

fn default_next() -> u16 {
    crate::LOW
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RootData {
    #[serde(default = "default_next")]
    next: u16,
    keys: BTreeMap<u16, RangeData>,
}

impl Default for RootData {
    fn default() -> Self {
        Self {
            next: crate::LOW,
            keys: Default::default(),
        }
    }
}

impl RootData {
    pub fn get_free_port_range(&mut self, range_size: u16) -> u16 {
        self.reclaim(now_ts());

        let mut base_port: u16 = self.next;
        'retry: loop {
            trace!(target: LOG_PORT_ALLOC, base_port, range_size, "Checking a port");
            if HIGH < base_port {
                self.reclaim(now_ts());
                base_port = LOW;
            }
            let range = base_port..base_port + range_size;
            if let Some(next_port) = self.contains(range.clone()) {
                warn!(
                    base_port,
                    range_size,
                    "Could not use a port (already reserved). Will try a different range."
                );
                base_port = next_port;
                continue 'retry;
            }

            for port in range.clone() {
                match TcpListener::bind(("127.0.0.1", port)) {
                    Err(error) => {
                        warn!(
                            ?error,
                            port, "Could not use a port. Will try a different range"
                        );
                        base_port = port + 1;
                        continue 'retry;
                    }
                    Ok(l) => l,
                };
            }

            const ALLOCATION_TIME_SECS: u64 = 120;

            // The caller gets some time actually start using the port (`bind`),
            // to prevent other callers from re-using it. This could typically be
            // much shorter, as portalloc will not only respect the allocation,
            // but also try to bind before using a given port range. But for tests
            // that temporarily release ports (e.g. restarts, failure simulations, etc.),
            // there's a chance that this can expire and another tests snatches the test,
            // so better to keep it around the time a longest test can take.
            self.insert(range, now_ts() + ALLOCATION_TIME_SECS);

            debug!(target: LOG_PORT_ALLOC, base_port, range_size, "Allocated port range");
            break base_port;
        }
    }

    fn reclaim(&mut self, now: u64) {
        self.keys.retain(|_k, v| now < v.expires);
    }

    /// Check if `range` conflicts with anything already reserved
    ///
    /// If it does return next address after the range that conflicted.
    fn contains(&self, range: std::ops::Range<u16>) -> Option<u16> {
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

    fn insert(&mut self, range: std::ops::Range<u16>, now_ts: u64) {
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

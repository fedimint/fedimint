use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::str::FromStr;

use fedimint_core::config::PeerUrl;
use serde::{Deserialize, Serialize};

use crate::encoding::{Decodable, Encodable};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct PeerId(u16);

impl PeerId {
    pub fn new(id: u16) -> Self {
        Self(id)
    }

    pub fn to_usize(self) -> usize {
        self.0 as usize
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PeerId {
    type Err = <u16 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(PeerId)
    }
}

impl From<u16> for PeerId {
    fn from(id: u16) -> Self {
        Self(id)
    }
}

impl From<PeerId> for u16 {
    fn from(peer: PeerId) -> Self {
        peer.0
    }
}

/// The number of guardians in a federation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NumPeers(usize);

impl NumPeers {
    /// Returns an iterator over all peer IDs in the federation.
    pub fn peer_ids(self) -> impl Iterator<Item = PeerId> {
        (0u16..(self.0 as u16)).map(PeerId)
    }

    /// Returns the total number of guardians in the federation.
    pub fn total(self) -> usize {
        self.0
    }

    /// Returns the number of guardians that can be evil without disrupting the
    /// federation.
    pub fn max_evil(self) -> usize {
        (self.total() - 1) / 3
    }

    /// Returns the number of guardians to select such that at least one is
    /// honest (assuming the federation is not compromised).
    pub fn one_honest(self) -> usize {
        self.max_evil() + 1
    }

    /// Returns the degree of an underlying polynomial to require threshold
    /// signatures.
    pub fn degree(self) -> usize {
        self.threshold() - 1
    }

    /// Returns the number of guardians required to achieve consensus and
    /// produce valid signatures.
    pub fn threshold(self) -> usize {
        self.total() - self.max_evil()
    }
}

impl From<usize> for NumPeers {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

/// Types that can be easily converted to [`NumPeers`]
pub trait NumPeersExt {
    fn to_num_peers(&self) -> NumPeers;
}

impl<T> From<T> for NumPeers
where
    T: NumPeersExt,
{
    fn from(value: T) -> Self {
        value.to_num_peers()
    }
}

impl<T> NumPeersExt for BTreeMap<PeerId, T> {
    fn to_num_peers(&self) -> NumPeers {
        NumPeers(self.len())
    }
}

impl NumPeersExt for &[PeerId] {
    fn to_num_peers(&self) -> NumPeers {
        NumPeers(self.len())
    }
}

impl NumPeersExt for Vec<PeerId> {
    fn to_num_peers(&self) -> NumPeers {
        NumPeers(self.len())
    }
}

impl NumPeersExt for Vec<PeerUrl> {
    fn to_num_peers(&self) -> NumPeers {
        NumPeers(self.len())
    }
}

impl NumPeersExt for BTreeSet<PeerId> {
    fn to_num_peers(&self) -> NumPeers {
        NumPeers(self.len())
    }
}

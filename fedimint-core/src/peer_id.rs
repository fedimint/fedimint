#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::num::NonZeroUsize;
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

#[cfg(feature = "uniffi")]
uniffi::custom_newtype!(PeerId, u16);

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
pub struct NumPeers(NonZeroUsize);

impl NumPeers {
    /// Constructs a guardian count, returning `None` when `total` is zero.
    pub const fn new(total: usize) -> Option<Self> {
        match NonZeroUsize::new(total) {
            Some(total) => Some(Self(total)),
            None => None,
        }
    }

    /// Returns an iterator over all peer IDs in the federation.
    pub fn peer_ids(self) -> impl Iterator<Item = PeerId> {
        (0u16..(self.total() as u16)).map(PeerId)
    }

    /// Returns the total number of guardians in the federation.
    pub fn total(self) -> usize {
        self.0.get()
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

impl TryFrom<usize> for NumPeers {
    type Error = EmptyPeerSet;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(EmptyPeerSet)
    }
}

/// Error returned when constructing [`NumPeers`] from a zero count.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EmptyPeerSet;

impl std::fmt::Display for EmptyPeerSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a federation must have at least one guardian")
    }
}

impl std::error::Error for EmptyPeerSet {}

/// Types that can be easily converted to [`NumPeers`]
pub trait NumPeersExt {
    /// Tries to return the number of guardians in this collection.
    fn try_num_peers(&self) -> Result<NumPeers, EmptyPeerSet>;

    /// Returns the number of guardians in this non-empty collection.
    ///
    /// # Panics
    ///
    /// Panics if the collection is empty.
    fn to_num_peers(&self) -> NumPeers {
        self.try_num_peers()
            .expect("peer collection must not be empty")
    }
}

impl<T> NumPeersExt for BTreeMap<PeerId, T> {
    fn try_num_peers(&self) -> Result<NumPeers, EmptyPeerSet> {
        NumPeers::try_from(self.len())
    }
}

impl NumPeersExt for &[PeerId] {
    fn try_num_peers(&self) -> Result<NumPeers, EmptyPeerSet> {
        NumPeers::try_from(self.len())
    }
}

impl NumPeersExt for Vec<PeerId> {
    fn try_num_peers(&self) -> Result<NumPeers, EmptyPeerSet> {
        NumPeers::try_from(self.len())
    }
}

impl NumPeersExt for Vec<PeerUrl> {
    fn try_num_peers(&self) -> Result<NumPeers, EmptyPeerSet> {
        NumPeers::try_from(self.len())
    }
}

impl NumPeersExt for BTreeSet<PeerId> {
    fn try_num_peers(&self) -> Result<NumPeers, EmptyPeerSet> {
        NumPeers::try_from(self.len())
    }
}

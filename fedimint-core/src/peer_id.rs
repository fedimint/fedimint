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
        self.total().saturating_sub(1) / 3
    }

    /// Returns the number of guardians to select such that at least one is
    /// honest (assuming the federation is not compromised).
    pub fn one_honest(self) -> usize {
        self.max_evil() + 1
    }

    /// Returns the degree of an underlying polynomial to require threshold
    /// signatures.
    pub fn degree(self) -> usize {
        self.threshold().saturating_sub(1)
    }

    /// Returns the number of guardians required to achieve consensus and
    /// produce valid signatures.
    pub fn threshold(self) -> usize {
        self.total().saturating_sub(self.max_evil())
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{NumPeers, NumPeersExt, PeerId};

    #[test]
    fn test_num_peers_zero_does_not_underflow() {
        let zero = NumPeers::from(0);
        assert_eq!(zero.total(), 0);
        assert_eq!(zero.max_evil(), 0);
        assert_eq!(zero.threshold(), 0);
        assert_eq!(zero.degree(), 0);
        assert_eq!(zero.one_honest(), 1);
    }

    #[test]
    fn test_empty_collections_to_num_peers() {
        let empty_vec: Vec<PeerId> = Vec::new();
        assert_eq!(empty_vec.to_num_peers().max_evil(), 0);
        assert_eq!(empty_vec.to_num_peers().threshold(), 0);

        let empty_map: BTreeMap<PeerId, ()> = BTreeMap::new();
        assert_eq!(empty_map.to_num_peers().max_evil(), 0);
        assert_eq!(empty_map.to_num_peers().threshold(), 0);

        let empty_set: BTreeSet<PeerId> = BTreeSet::new();
        assert_eq!(empty_set.to_num_peers().max_evil(), 0);
        assert_eq!(empty_set.to_num_peers().threshold(), 0);
    }

    #[test]
    fn test_num_peers_standard_topologies() {
        // 1 peer: f = 0, threshold = 1, degree = 0
        let one = NumPeers::from(1);
        assert_eq!(one.max_evil(), 0);
        assert_eq!(one.threshold(), 1);
        assert_eq!(one.degree(), 0);

        // 4 peers: f = 1, threshold = 3, degree = 2
        let four = NumPeers::from(4);
        assert_eq!(four.max_evil(), 1);
        assert_eq!(four.threshold(), 3);
        assert_eq!(four.degree(), 2);

        // 7 peers: f = 2, threshold = 5, degree = 4
        let seven = NumPeers::from(7);
        assert_eq!(seven.max_evil(), 2);
        assert_eq!(seven.threshold(), 5);
        assert_eq!(seven.degree(), 4);

        // 10 peers: f = 3, threshold = 7, degree = 6
        let ten = NumPeers::from(10);
        assert_eq!(ten.max_evil(), 3);
        assert_eq!(ten.threshold(), 7);
        assert_eq!(ten.degree(), 6);
    }
}

use bitcoin::hashes::{sha256, Hash};
use parity_scale_codec::{Decode, Encode};

use crate::encoding::{Decodable, Encodable};
use crate::epoch::ConsensusItem;
use crate::PeerId;

/// If two correct nodes obtain two ordered items from the broadcast they
/// are guaranteed to be in the same order. However, an ordered items is
/// only guaranteed to be seen by all correct nodes if a correct node decides to
/// accept it.
#[derive(Clone, Debug, PartialEq, Eq, Encodable, Decodable)]
pub struct AcceptedItem {
    pub item: ConsensusItem,
    pub peer: PeerId,
}

/// Items ordered in a single session that have been accepted by Fedimint
/// consensus.
///
/// A running Federation produces a [`SessionOutcome`] every couple of minutes.
/// Therefore, just like in Bitcoin, a [`SessionOutcome`] might be empty if no
/// items are ordered in that time or all ordered items are discarded by
/// Fedimint Consensus.
///
/// When session is closed it is signed over by the peers and produces a
/// [`SignedSessionOutcome`].
#[derive(Clone, Debug, PartialEq, Eq, Encodable, Decodable)]
pub struct SessionOutcome {
    pub items: Vec<AcceptedItem>,
}

impl SessionOutcome {
    /// A blocks header consists of 40 bytes formed by its index in big endian
    /// bytes concatenated with the merkle root build from the consensus
    /// hashes of its [`AcceptedItem`]s or 32 zero bytes if the block is
    /// empty. The use of a merkle tree allows for efficient inclusion
    /// proofs of accepted consensus items for clients.
    pub fn header(&self, index: u64) -> [u8; 40] {
        let mut header = [0; 40];

        header[..8].copy_from_slice(&index.to_be_bytes());

        let leaf_hashes = self
            .items
            .iter()
            .map(Encodable::consensus_hash::<sha256::Hash>);

        if let Some(root) = bitcoin::merkle_tree::calculate_root(leaf_hashes) {
            header[8..].copy_from_slice(&root.to_byte_array());
        }

        header
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Encode, Decode, PartialEq, Eq, Hash)]
pub struct SchnorrSignature(pub [u8; 64]);

/// A [`SessionOutcome`], signed by the Federation.
///
/// A signed block combines a block with the naive threshold secp schnorr
/// signature for its header created by the federation. The signed blocks allow
/// clients and recovering guardians to verify the federations consensus
/// history. After a signed block has been created it is stored in the database.
#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq)]
pub struct SignedSessionOutcome {
    pub session_outcome: SessionOutcome,
    pub signatures: std::collections::BTreeMap<PeerId, SchnorrSignature>,
}

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub enum SessionStatus {
    Initial,
    Pending(Vec<AcceptedItem>),
    Complete(SessionOutcome),
}

use bitcoin30::hashes::{sha256, Hash};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::encoding::{Decodable, Encodable};
use crate::PeerId;

/// If two correct nodes obtain two ordered items from the broadcast they
/// are guaranteed to be in the same order. However, an ordered items is
/// only guaranteed to be seen by all correct nodes if a correct node decides to
/// accept it.
#[derive(Clone, Debug, PartialEq, Eq, Encodable, Decodable, Deserialize, Serialize)]
pub struct OrderedItem {
    pub item: Vec<u8>,
    pub index: u64,
    pub peer_id: PeerId,
}

/// All items ordered in a session that have been accepted by Fedimint Consensus
/// are recorded in the corresponding block. A running Federation produces a
/// [Block] roughly every five minutes.  Therefore, just like in Bitcoin, a
/// [Block] might be empty if no items are ordered in that time or all ordered
/// items are discarded by Fedimint Consensus.
#[derive(Clone, Debug, PartialEq, Eq, Encodable, Decodable, Deserialize, Serialize)]
pub struct Block {
    pub index: u64,
    pub items: Vec<OrderedItem>,
}

impl Block {
    /// A blocks header consists of 40 bytes formed by its index in big endian
    /// bytes concatenated with the merkle root build from the consensus
    /// hashes of its [OrderedItem]s or 32 zero bytes if the block is
    /// empty. The use of a merkle tree allows for efficient inclusion
    /// proofs of accepted consensus items for clients.
    pub fn header(&self) -> [u8; 40] {
        let mut header = [0; 40];

        header[..8].copy_from_slice(&self.index.to_be_bytes());

        let leaf_hashes = self.items.iter().map(consensus_hash_sha256);

        // TODO: extract merkle tree calculation and remove bitcoin dep
        if let Some(root) = bitcoin30::merkle_tree::calculate_root(leaf_hashes) {
            header[8..].copy_from_slice(&root.to_byte_array());
        }

        header
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Encode, Decode, PartialEq, Eq, Hash)]
pub struct SchnorrSignature(pub [u8; 64]);

impl Serialize for SchnorrSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Simply serialize the byte array as a sequence of u8 values.
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SchnorrSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize as a byte array. Ensure it has the correct length.
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() == 64 {
            let mut array = [0u8; 64];
            array.copy_from_slice(&bytes);
            Ok(SchnorrSignature(array))
        } else {
            Err(serde::de::Error::invalid_length(bytes.len(), &"length 64"))
        }
    }
}

/// A signed block combines a block with the naive threshold secp schnorr
/// signature for its header created by the federation. The signed blocks allow
/// clients and recovering guardians to verify the federations consensus
/// history. After a signed block has been created it is stored in the database.
#[derive(Clone, Debug, Encodable, Decodable, Serialize, Deserialize, Eq, PartialEq)]
pub struct SignedBlock {
    pub block: Block,
    pub signatures: std::collections::BTreeMap<PeerId, SchnorrSignature>,
}

// TODO: remove this as soon as we bump bitcoin_hashes in fedimint_core to
// 0.12.0
pub fn consensus_hash_sha256<E: Encodable>(encodable: &E) -> sha256::Hash {
    let mut engine = sha256::HashEngine::default();
    encodable
        .consensus_encode(&mut engine)
        .expect("Writing to HashEngine cannot fail");
    sha256::Hash::from_engine(engine)
}

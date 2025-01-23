use std::borrow::Cow;
use std::hash::Hash;
use std::io::Cursor;

use bitcoin::block::Header as BlockHeader;
use bitcoin::merkle_tree::PartialMerkleTree;
use bitcoin::{BlockHash, Txid};
use hex::FromHex;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::module::registry::ModuleDecoderRegistry;

#[derive(Clone, Debug)]
pub struct TxOutProof {
    pub block_header: BlockHeader,
    pub merkle_proof: PartialMerkleTree,
}

impl TxOutProof {
    pub fn block(&self) -> BlockHash {
        self.block_header.block_hash()
    }

    pub fn contains_tx(&self, tx_id: Txid) -> bool {
        let mut transactions = Vec::new();
        let mut indices = Vec::new();
        let root = self
            .merkle_proof
            .extract_matches(&mut transactions, &mut indices)
            .expect("Checked at construction time");

        debug_assert_eq!(root, self.block_header.merkle_root);

        transactions.contains(&tx_id)
    }
}

impl Decodable for TxOutProof {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let block_header = BlockHeader::consensus_decode_partial(d, modules)?;
        let merkle_proof = PartialMerkleTree::consensus_decode_partial(d, modules)?;

        let mut transactions = Vec::new();
        let mut indices = Vec::new();
        let root = merkle_proof
            .extract_matches(&mut transactions, &mut indices)
            .map_err(|_| DecodeError::from_str("Invalid partial merkle tree"))?;

        if block_header.merkle_root == root {
            Ok(Self {
                block_header,
                merkle_proof,
            })
        } else {
            Err(DecodeError::from_str(
                "Partial merkle tree does not belong to block header",
            ))
        }
    }
}

impl Encodable for TxOutProof {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.block_header.consensus_encode(writer)?;
        self.merkle_proof.consensus_encode(writer)?;

        Ok(())
    }
}

impl Serialize for TxOutProof {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.consensus_encode_to_hex())
        } else {
            serializer.serialize_bytes(&self.consensus_encode_to_vec())
        }
    }
}

impl<'de> Deserialize<'de> for TxOutProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let empty_module_registry = ModuleDecoderRegistry::default();
        if deserializer.is_human_readable() {
            let hex_str: Cow<str> = Deserialize::deserialize(deserializer)?;
            let bytes = Vec::from_hex(hex_str.as_ref()).map_err(D::Error::custom)?;
            Ok(
                Self::consensus_decode_partial(&mut Cursor::new(bytes), &empty_module_registry)
                    .map_err(D::Error::custom)?,
            )
        } else {
            let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
            Ok(
                Self::consensus_decode_partial(&mut Cursor::new(bytes), &empty_module_registry)
                    .map_err(D::Error::custom)?,
            )
        }
    }
}

// TODO: upstream
impl Hash for TxOutProof {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.consensus_encode_to_vec());
    }
}

impl PartialEq for TxOutProof {
    fn eq(&self, other: &Self) -> bool {
        self.block_header == other.block_header && self.merkle_proof == other.merkle_proof
    }
}

impl Eq for TxOutProof {}

use std::borrow::Cow;
use std::hash::Hash;
use std::io::Cursor;

use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::{BlockHash, BlockHeader, Txid};
use bitcoin_hashes::hex::{FromHex, ToHex};
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
    fn consensus_decode<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let block_header = BlockHeader::consensus_decode(d, modules)?;
        let merkle_proof = PartialMerkleTree::consensus_decode(d, modules)?;

        let mut transactions = Vec::new();
        let mut indices = Vec::new();
        let root = merkle_proof
            .extract_matches(&mut transactions, &mut indices)
            .map_err(|_| DecodeError::from_str("Invalid partial merkle tree"))?;

        if block_header.merkle_root != root {
            Err(DecodeError::from_str(
                "Partial merkle tree does not belong to block header",
            ))
        } else {
            Ok(TxOutProof {
                block_header,
                merkle_proof,
            })
        }
    }
}

impl Encodable for TxOutProof {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let mut written = 0;

        written += self.block_header.consensus_encode(writer)?;
        written += self.merkle_proof.consensus_encode(writer)?;

        Ok(written)
    }
}

impl Serialize for TxOutProof {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        self.consensus_encode(&mut bytes).unwrap();

        if serializer.is_human_readable() {
            serializer.serialize_str(&bytes.to_hex())
        } else {
            serializer.serialize_bytes(&bytes)
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
            let bytes = Vec::from_hex(&hex_str).map_err(D::Error::custom)?;
            Ok(
                TxOutProof::consensus_decode(&mut Cursor::new(bytes), &empty_module_registry)
                    .map_err(D::Error::custom)?,
            )
        } else {
            let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
            Ok(
                TxOutProof::consensus_decode(&mut Cursor::new(bytes), &empty_module_registry)
                    .map_err(D::Error::custom)?,
            )
        }
    }
}

// TODO: upstream
impl Hash for TxOutProof {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let mut bytes = Vec::new();
        self.consensus_encode(&mut bytes).unwrap();
        state.write(&bytes);
    }
}

impl PartialEq for TxOutProof {
    fn eq(&self, other: &TxOutProof) -> bool {
        self.block_header == other.block_header && self.merkle_proof == other.merkle_proof
    }
}

impl Eq for TxOutProof {}

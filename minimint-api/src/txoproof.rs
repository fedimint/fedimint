use crate::encoding::{Decodable, DecodeError, Encodable};
use crate::keys::CompressedPublicKey;
use crate::{Contract, Tweakable};
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::{BlockHash, BlockHeader, OutPoint, Transaction, Txid};
use miniscript::{Descriptor, DescriptorTrait, TranslatePk2};
use secp256k1_zkp::{Secp256k1, Verification};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::hash::Hash;
use std::io::Cursor;
use thiserror::Error;
use validator::{Validate, ValidationError};

/// A proof about a script owning a certain output. Verifyable using headers only.
#[derive(Clone, Debug, PartialEq, Serialize, Eq, Hash, Deserialize, Validate, Encodable)]
#[validate(schema(function = "validate_peg_in_proof"))]
pub struct PegInProof {
    txout_proof: TxOutProof,
    // check that outputs are not more than u32::max (probably enforced if inclusion proof is
    // checked first) and that the referenced output has a value that won't overflow when converted
    // to msat
    transaction: Transaction,
    // Check that the idx is in range
    output_idx: u32,
    tweak_contract_key: secp256k1_zkp::schnorrsig::PublicKey,
}

#[derive(Clone, Debug)]
pub struct TxOutProof {
    block_header: BlockHeader,
    merkle_proof: PartialMerkleTree,
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
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let block_header = BlockHeader::consensus_decode(&mut d)?;
        let merkle_proof = PartialMerkleTree::consensus_decode(&mut d)?;

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
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        let mut written = 0;

        written += self.block_header.consensus_encode(&mut writer)?;
        written += self.merkle_proof.consensus_encode(&mut writer)?;

        Ok(written)
    }
}

impl PegInProof {
    pub fn new(
        txout_proof: TxOutProof,
        transaction: Transaction,
        output_idx: u32,
        tweak_contract_key: secp256k1_zkp::schnorrsig::PublicKey,
    ) -> Result<PegInProof, PegInProofError> {
        // TODO: remove redundancy with serde validation
        if !txout_proof.contains_tx(transaction.txid()) {
            return Err(PegInProofError::TransactionNotInProof);
        }

        if transaction.output.len() > u32::MAX as usize {
            return Err(PegInProofError::TooManyTransactionOutputs);
        }

        if transaction.output.get(output_idx as usize).is_none() {
            return Err(PegInProofError::OutputIndexOutOfRange(
                output_idx as usize,
                transaction.output.len(),
            ));
        }

        Ok(PegInProof {
            txout_proof,
            transaction,
            output_idx,
            tweak_contract_key,
        })
    }

    pub fn verify<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        untweaked_pegin_descriptor: &Descriptor<CompressedPublicKey>,
    ) -> Result<(), PegInProofError> {
        let script = untweaked_pegin_descriptor
            .tweak(&self.tweak_contract_key, secp)
            .script_pubkey();

        let txo = self
            .transaction
            .output
            .get(self.output_idx as usize)
            .expect("output_idx in-rangeness is an invariant guaranteed by constructors");

        if txo.script_pubkey != script {
            return Err(PegInProofError::ScriptDoesNotMatch);
        }

        Ok(())
    }

    pub fn proof_block(&self) -> BlockHash {
        self.txout_proof.block()
    }

    pub fn tweak_contract_key(&self) -> &secp256k1_zkp::schnorrsig::PublicKey {
        &self.tweak_contract_key
    }

    pub fn identity(&self) -> (secp256k1_zkp::schnorrsig::PublicKey, bitcoin::Txid) {
        (self.tweak_contract_key, self.transaction.txid())
    }

    pub fn tx_output(&self) -> &bitcoin::TxOut {
        self.transaction
            .output
            .get(self.output_idx as usize)
            .expect("output_idx in-rangeness is an invariant guaranteed by constructors")
    }

    pub fn outpoint(&self) -> bitcoin::OutPoint {
        OutPoint {
            txid: self.transaction.txid(),
            vout: self.output_idx,
        }
    }
}

impl Tweakable for Descriptor<CompressedPublicKey> {
    fn tweak<Ctx: Verification, Ctr: Contract>(&self, tweak: &Ctr, secp: &Secp256k1<Ctx>) -> Self {
        self.translate_pk2_infallible(|pk| CompressedPublicKey {
            key: pk.key.tweak(tweak, secp),
        })
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
            serializer.serialize_str(&hex::encode(&bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for TxOutProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let hex_str: &str = Deserialize::deserialize(deserializer)?;
            let bytes = hex::decode(hex_str).map_err(<D as Deserializer<'de>>::Error::custom)?;
            Ok(TxOutProof::consensus_decode(Cursor::new(bytes))
                .map_err(<D as Deserializer<'de>>::Error::custom)?)
        } else {
            let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
            Ok(TxOutProof::consensus_decode(Cursor::new(bytes))
                .map_err(<D as Deserializer<'de>>::Error::custom)?)
        }
    }
}

fn validate_peg_in_proof(proof: &PegInProof) -> Result<(), ValidationError> {
    if !proof.txout_proof.contains_tx(proof.transaction.txid()) {
        return Err(ValidationError::new(
            "Supplied transaction is not included in proof",
        ));
    }

    if proof.transaction.output.len() > u32::MAX as usize {
        return Err(ValidationError::new(
            "Supplied transaction has too many outputs",
        ));
    }

    match proof.transaction.output.get(proof.output_idx as usize) {
        Some(txo) => {
            if txo.value > 2_100_000_000_000_000 {
                return Err(ValidationError::new("Txout amount out of range"));
            }
        }
        None => {
            return Err(ValidationError::new("Output index out of range"));
        }
    }

    Ok(())
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

impl Decodable for PegInProof {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, DecodeError> {
        let slf = PegInProof {
            txout_proof: TxOutProof::consensus_decode(&mut d)?,
            transaction: Transaction::consensus_decode(&mut d)?,
            output_idx: u32::consensus_decode(&mut d)?,
            tweak_contract_key: secp256k1_zkp::schnorrsig::PublicKey::consensus_decode(&mut d)?,
        };

        validate_peg_in_proof(&slf).map_err(DecodeError::from_err)?;
        Ok(slf)
    }
}

#[derive(Debug, Error)]
pub enum PegInProofError {
    #[error("Supplied transaction is not included in proof")]
    TransactionNotInProof,
    #[error("Supplied transaction has too many outputs")]
    TooManyTransactionOutputs,
    #[error("The output with index {0} referred to does not exist (tx has {1} outputs)")]
    OutputIndexOutOfRange(usize, usize),
    #[error("The expected script given the tweak did not match the actual script")]
    ScriptDoesNotMatch,
}

#[cfg(test)]
mod tests {
    use super::TxOutProof;
    use crate::encoding::Decodable;
    use std::io::Cursor;

    #[test]
    fn test_txoutproof_happy_path() {
        let txoutproof_hex = "0000a020c7f74cb7d4cbf90a40f38b8194d17996d29ad8cb8d42030000000000000\
        0000045e274cbfff8fe34e6df61079ae8c8cf5af6d53ff158488e26df5a072363693be15a6760482a0c1731b169\
        074a0a00000dc525bdf029c9d77ac1039826be603bf08837d5dfd58b763590fb3f2db32693eacd2a8b13842289e\
        d8b6b10ffbae3498987ca510d6b54a278bb85a9b6f2daa0efa52ae55f39842e890144f998258b365ae903fd5b8e\
        32b651acc65682378db2ac8376b8a8ed3777f297e5ec354ff31b80c79fd40e0aa8e961b582959db470a25db8bb8\
        0f87602a7b53fe0d0ecd3597d03b75e1af64cb229eb680daec7848e78fcf822717de5268738d49b610dd8f8eb22\
        2fa477bc85d46582c4aaa659848c8aac9440e429110c5848517b8459fd91fc8bf5ec6740c708e2980ddf4070f7f\
        c2c14247830c014b559c6fb3dad9408237a78bb2bca0b2016a3c4cac2e450a09b78e1a78fcb9fd1edc4989a5ae6\
        ba438b81a400a22fa172da6e2bec5b67e21841e975a696b51dff22d12dcc27417f9017b0fedcf7bbf7ae4c1d278\
        d92c364b1a1675855927a8a8f22e1e3441bb3389d7d82e57d68b46fe946546e7aea7f58ed3ae5aec4b3b99ca87e\
        9602cb7c776730435c1713a1ca57c0c6761576fbfb17da642aae2a4ce874e32b5c0cba450163b14b6b94bc479cb\
        58a30f7ae5b909ffdd020073f04ff370000";

        let txoutproof =
            TxOutProof::consensus_decode(Cursor::new(hex::decode(txoutproof_hex).unwrap()))
                .unwrap();

        assert_eq!(
            txoutproof.block(),
            "0000000000000000000761505b672f2f7fc3822a5a95089fa469c3fb16ee574b"
                .parse()
                .unwrap()
        );

        assert!(txoutproof.contains_tx(
            "efa0daf2b6a985bb78a2546b0d51ca878949e3baff106b8bed892284138b2acd"
                .parse()
                .unwrap()
        ))
    }
}

use crate::keys::CompressedPublicKey;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::{sha256, Hash as BitcoinHash, HashEngine, Hmac, HmacEngine};
use bitcoin::util::merkleblock::PartialMerkleTree;
use bitcoin::{Amount, BlockHash, BlockHeader, OutPoint, PublicKey, Transaction, Txid};
use miniscript::{Descriptor, DescriptorTrait, TranslatePk, TranslatePk2};
use secp256k1::{Secp256k1, Verification};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::Cursor;
use thiserror::Error;
use validator::{Validate, ValidationError};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Validate)]
#[validate(schema(function = "validate_peg_in_proof"))]
pub struct PegInProof {
    txout_proof: TxOutProof,
    // check that outputs are not more than u32::max (probably enforced if inclusion proof is checked first)
    transaction: Transaction,
    tweak_contract_key: secp256k1::PublicKey,
}

#[derive(Clone, Debug, PartialEq)]
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
    fn consensus_decode<D: std::io::Read>(
        mut d: D,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let block_header = BlockHeader::consensus_decode(&mut d)?;
        let merkle_proof = PartialMerkleTree::consensus_decode(&mut d)?;

        let mut transactions = Vec::new();
        let mut indices = Vec::new();
        let root = merkle_proof
            .extract_matches(&mut transactions, &mut indices)
            .map_err(|e| {
                bitcoin::consensus::encode::Error::ParseFailed("Invalid partial merkle tree")
            })?;

        if block_header.merkle_root != root {
            Err(bitcoin::consensus::encode::Error::ParseFailed(
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
        tweak_contract_key: secp256k1::PublicKey,
    ) -> Result<PegInProof, PegInProofError> {
        // TODO: remove redundancy with serde validation
        if !txout_proof.contains_tx(transaction.txid()) {
            return Err(PegInProofError::TransactionNotInProof);
        }

        if transaction.output.len() > u32::MAX as usize {
            return Err(PegInProofError::TooManyTransactionOutputs);
        }

        Ok(PegInProof {
            txout_proof,
            transaction,
            tweak_contract_key,
        })
    }

    pub fn get_our_tweaked_txos<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        untweaked_pegin_descriptor: Descriptor<CompressedPublicKey>,
    ) -> Vec<(OutPoint, Amount)> {
        let script = untweaked_pegin_descriptor
            .translate_pk2_infallible(|pk| CompressedPublicKey {
                key: tweak_key(secp, pk.key, self.tweak_contract_key),
            })
            .script_pubkey();

        self.transaction
            .output
            .iter()
            .enumerate()
            .filter_map(|(idx, txo)| {
                if txo.script_pubkey == script {
                    let out_point = OutPoint {
                        txid: self.transaction.txid(),
                        vout: idx as u32,
                    };
                    Some((out_point, Amount::from_sat(txo.value)))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn proof_block(&self) -> BlockHash {
        self.txout_proof.block()
    }

    pub fn tweak_contract_key(&self) -> &secp256k1::PublicKey {
        &self.tweak_contract_key
    }
}

/// Hashes the `tweak` key together with the `key` and uses the result to tweak the `key`
fn tweak_key<C: Verification>(
    secp: &Secp256k1<C>,
    mut key: secp256k1::PublicKey,
    tweak: secp256k1::PublicKey,
) -> secp256k1::PublicKey {
    let mut hasher = HmacEngine::<sha256::Hash>::new(&key.serialize()[..]);
    hasher.input(&tweak.serialize()[..]);
    let tweak = Hmac::from_engine(hasher).into_inner();

    key.add_exp_assign(secp, &tweak[..])
        .expect("tweak is always 32 bytes, other failure modes are negligible");
    key
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
            let bytes =
                hex::decode(hex_str).map_err(|e| <D as Deserializer<'de>>::Error::custom(e))?;
            Ok(TxOutProof::consensus_decode(Cursor::new(bytes))
                .map_err(|e| <D as Deserializer<'de>>::Error::custom(e))?)
        } else {
            let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
            Ok(TxOutProof::consensus_decode(Cursor::new(bytes))
                .map_err(|e| <D as Deserializer<'de>>::Error::custom(e))?)
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

    Ok(())
}

#[derive(Debug, Error)]
pub enum PegInProofError {
    #[error("Supplied transaction is not included in proof")]
    TransactionNotInProof,
    #[error("Supplied transaction has too many outputs")]
    TooManyTransactionOutputs,
}

#[cfg(test)]
mod tests {
    use crate::txoproof::TxOutProof;
    use bitcoin::consensus::Decodable;
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

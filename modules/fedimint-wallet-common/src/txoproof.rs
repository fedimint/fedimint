use std::convert::Infallible;
use std::hash::Hash;

use anyhow::format_err;
use bitcoin::secp256k1::{PublicKey, Secp256k1, Signing, Verification};
use bitcoin::{Amount, BlockHash, OutPoint, Transaction};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::txoproof::TxOutProof;
use miniscript::{Descriptor, TranslatePk, translate_hash_fail};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::keys::CompressedPublicKey;
use crate::tweakable::{Contract, Tweakable};

/// A proof about a script owning a certain output. Verifiable using headers
/// only.
#[derive(Clone, Debug, PartialEq, Serialize, Eq, Hash, Encodable)]
pub struct PegInProof {
    txout_proof: TxOutProof,
    // check that outputs are not more than u32::max (probably enforced if inclusion proof is
    // checked first) and that the referenced output has a value that won't overflow when converted
    // to msat
    transaction: Transaction,
    // Check that the idx is in range
    output_idx: u32,
    tweak_contract_key: PublicKey,
}

impl<'de> Deserialize<'de> for PegInProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct PegInProofInner {
            txout_proof: TxOutProof,
            transaction: Transaction,
            output_idx: u32,
            tweak_contract_key: PublicKey,
        }

        let pegin_proof_inner = PegInProofInner::deserialize(deserializer)?;

        let pegin_proof = PegInProof {
            txout_proof: pegin_proof_inner.txout_proof,
            transaction: pegin_proof_inner.transaction,
            output_idx: pegin_proof_inner.output_idx,
            tweak_contract_key: pegin_proof_inner.tweak_contract_key,
        };

        validate_peg_in_proof(&pegin_proof).map_err(D::Error::custom)?;

        Ok(pegin_proof)
    }
}

impl PegInProof {
    pub fn new(
        txout_proof: TxOutProof,
        transaction: Transaction,
        output_idx: u32,
        tweak_contract_key: PublicKey,
    ) -> Result<PegInProof, PegInProofError> {
        // TODO: remove redundancy with serde validation
        if !txout_proof.contains_tx(transaction.compute_txid()) {
            return Err(PegInProofError::TransactionNotInProof);
        }

        if transaction.output.len() > u32::MAX as usize {
            return Err(PegInProofError::TooManyTransactionOutputs);
        }

        if transaction.output.get(output_idx as usize).is_none() {
            return Err(PegInProofError::OutputIndexOutOfRange(
                u64::from(output_idx),
                transaction.output.len() as u64,
            ));
        }

        Ok(PegInProof {
            txout_proof,
            transaction,
            output_idx,
            tweak_contract_key,
        })
    }

    pub fn verify<C: Verification + Signing>(
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

    pub fn tweak_key(&self) -> PublicKey {
        self.tweak_contract_key
    }

    pub fn identity(&self) -> (PublicKey, bitcoin::Txid) {
        (self.tweak_contract_key, self.transaction.compute_txid())
    }

    pub fn tx_output(&self) -> bitcoin::TxOut {
        self.transaction
            .output
            .get(self.output_idx as usize)
            .expect("output_idx in-rangeness is an invariant guaranteed by constructors")
            .clone()
    }

    pub fn outpoint(&self) -> bitcoin::OutPoint {
        OutPoint {
            txid: self.transaction.compute_txid(),
            vout: self.output_idx,
        }
    }
}

impl Tweakable for Descriptor<CompressedPublicKey> {
    fn tweak<Ctx: Verification + Signing, Ctr: Contract>(
        &self,
        tweak: &Ctr,
        secp: &Secp256k1<Ctx>,
    ) -> Self {
        struct CompressedPublicKeyTranslator<'t, 's, Ctx: Verification, Ctr: Contract> {
            tweak: &'t Ctr,
            secp: &'s Secp256k1<Ctx>,
        }

        impl<Ctx: Verification + Signing, Ctr: Contract>
            miniscript::Translator<CompressedPublicKey, CompressedPublicKey, Infallible>
            for CompressedPublicKeyTranslator<'_, '_, Ctx, Ctr>
        {
            fn pk(&mut self, pk: &CompressedPublicKey) -> Result<CompressedPublicKey, Infallible> {
                Ok(CompressedPublicKey::new(
                    pk.key.tweak(self.tweak, self.secp),
                ))
            }

            translate_hash_fail!(
                CompressedPublicKey,
                miniscript::bitcoin::PublicKey,
                Infallible
            );
        }
        self.translate_pk(&mut CompressedPublicKeyTranslator { tweak, secp })
            .expect("can't fail")
    }
}

fn validate_peg_in_proof(proof: &PegInProof) -> Result<(), anyhow::Error> {
    if !proof
        .txout_proof
        .contains_tx(proof.transaction.compute_txid())
    {
        return Err(format_err!("Supplied transaction is not included in proof",));
    }

    if proof.transaction.output.len() > u32::MAX as usize {
        return Err(format_err!("Supplied transaction has too many outputs",));
    }

    match proof.transaction.output.get(proof.output_idx as usize) {
        Some(txo) => {
            if txo.value > Amount::MAX_MONEY {
                return Err(format_err!("Txout amount out of range"));
            }
        }
        None => {
            return Err(format_err!("Output index out of range"));
        }
    }

    Ok(())
}

impl Decodable for PegInProof {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let slf = PegInProof {
            txout_proof: TxOutProof::consensus_decode_partial(d, modules)?,
            transaction: Transaction::consensus_decode_partial(d, modules)?,
            output_idx: u32::consensus_decode_partial(d, modules)?,
            tweak_contract_key: PublicKey::consensus_decode_partial(d, modules)?,
        };

        validate_peg_in_proof(&slf).map_err(DecodeError::new_custom)?;
        Ok(slf)
    }
}

#[derive(Debug, Error, Encodable, Decodable, Hash, Clone, Eq, PartialEq)]
pub enum PegInProofError {
    #[error("Supplied transaction is not included in proof")]
    TransactionNotInProof,
    #[error("Supplied transaction has too many outputs")]
    TooManyTransactionOutputs,
    #[error("The output with index {0} referred to does not exist (tx has {1} outputs)")]
    OutputIndexOutOfRange(u64, u64),
    #[error("The expected script given the tweak did not match the actual script")]
    ScriptDoesNotMatch,
}

#[cfg(test)]
mod tests {
    use fedimint_core::encoding::Decodable;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::txoproof::TxOutProof;
    use hex::FromHex;

    #[test_log::test]
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

        let empty_module_registry = ModuleDecoderRegistry::default();
        let txoutproof = TxOutProof::consensus_decode_whole(
            &Vec::from_hex(txoutproof_hex).unwrap(),
            &empty_module_registry,
        )
        .unwrap();

        assert_eq!(
            txoutproof.block(),
            "0000000000000000000761505b672f2f7fc3822a5a95089fa469c3fb16ee574b"
                .parse()
                .unwrap()
        );

        assert!(
            txoutproof.contains_tx(
                "efa0daf2b6a985bb78a2546b0d51ca878949e3baff106b8bed892284138b2acd"
                    .parse()
                    .unwrap()
            )
        );
    }
}

use std::convert::Infallible;
use std::hash::Hash;

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

fn validate_peg_in_proof(proof: &PegInProof) -> Result<(), PegInProofValidationError> {
    if !proof
        .txout_proof
        .contains_tx(proof.transaction.compute_txid())
    {
        return Err(PegInProofValidationError::TransactionNotInProof);
    }

    if proof.transaction.output.len() > u32::MAX as usize {
        return Err(PegInProofValidationError::TooManyOutputs);
    }

    match proof.transaction.output.get(proof.output_idx as usize) {
        Some(txo) => {
            if txo.value > Amount::MAX_MONEY {
                return Err(PegInProofValidationError::AmountOutOfRange);
            }
        }
        None => {
            return Err(PegInProofValidationError::OutputIndexOutOfRange);
        }
    }

    Ok(())
}

/// Why a decoded [`PegInProof`] is not valid.
#[derive(Debug, Error)]
enum PegInProofValidationError {
    /// The proof does not contain the transaction.
    #[error("Supplied transaction is not included in proof")]
    TransactionNotInProof,

    /// The transaction has more outputs than an output index can address.
    #[error("Supplied transaction has too many outputs")]
    TooManyOutputs,

    /// The proven output's amount is more than all bitcoin there can be.
    #[error("Txout amount out of range")]
    AmountOutOfRange,

    /// The transaction has no output at the proof's output index.
    #[error("Output index out of range")]
    OutputIndexOutOfRange,
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

        validate_peg_in_proof(&slf).map_err(|error| DecodeError::Invalid(error.into()))?;
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
mod tests;

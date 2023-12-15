use bitcoin::hashes::Hash as BitcoinHash;
use fedimint_core::core::{DynInput, DynOutput};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::SerdeModuleEncoding;
use fedimint_core::{Amount, TransactionId};
use secp256k1_zkp::schnorr;
use thiserror::Error;

use crate::config::ALEPH_BFT_UNIT_BYTE_LIMIT;
use crate::core::{DynInputError, DynOutputError};

/// An atomic value transfer operation within the Fedimint system and consensus
///
/// The mint enforces that the total value of the outputs equals the total value
/// of the inputs, to prevent creating funds out of thin air. In some cases, the
/// value of the inputs and outputs can both be 0 e.g. when creating an offer to
/// a Lightning Gateway.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct Transaction {
    /// [`DynInput`]s consumed by the transaction
    pub inputs: Vec<DynInput>,
    /// [`DynOutput`]s created as a result of the transaction
    pub outputs: Vec<DynOutput>,
    /// No defined meaning, can be used to send the otherwise exactly same
    /// transaction multiple times if the module inputs and outputs don't
    /// introduce enough entropy.
    ///
    /// In the future the nonce can be used for grinding a tx hash that fulfills
    /// certain PoW requirements.
    pub nonce: [u8; 8],
    /// signatures for all the public keys of the inputs
    pub signatures: TransactionSignature,
}

pub type SerdeTransaction = SerdeModuleEncoding<Transaction>;

impl Transaction {
    /// Maximum size that a transaction can have while still fitting into an
    /// AlephBFT unit. Subtracting 32 bytes is overly conservative, even in the
    /// worst case the CI serialization around the transaction should never add
    /// that much overhead. But since the byte limit is 50kb right now a few
    /// bytes more or less won't make a difference and we can afford the safety
    /// margin.
    ///
    /// A realistic value would be 7:
    ///  * 1 byte for length of vector of CIs
    ///  * 1 byte for the CI enum variant
    ///  * 5 byte for the CI enum variant length
    pub const MAX_TX_SIZE: usize = ALEPH_BFT_UNIT_BYTE_LIMIT - 32;

    /// Hash of the transaction (excluding the signature).
    ///
    /// Transaction signature commits to this hash.
    /// To generate it without already having a signature use
    /// [`Self::tx_hash_from_parts`].
    pub fn tx_hash(&self) -> TransactionId {
        Self::tx_hash_from_parts(&self.inputs, &self.outputs, self.nonce)
    }

    /// Generate the transaction hash.
    pub fn tx_hash_from_parts(
        inputs: &[DynInput],
        outputs: &[DynOutput],
        nonce: [u8; 8],
    ) -> TransactionId {
        let mut engine = TransactionId::engine();
        inputs
            .consensus_encode(&mut engine)
            .expect("write to hash engine can't fail");
        outputs
            .consensus_encode(&mut engine)
            .expect("write to hash engine can't fail");
        nonce
            .consensus_encode(&mut engine)
            .expect("write to hash engine can't fail");
        TransactionId::from_engine(engine)
    }

    /// Validate the schnorr signatures signed over the `tx_hash`
    pub fn validate_signatures(
        &self,
        pub_keys: Vec<secp256k1_zkp::PublicKey>,
    ) -> Result<(), TransactionError> {
        let signatures = match &self.signatures {
            TransactionSignature::NaiveMultisig(sigs) => sigs,
            TransactionSignature::Default { variant, .. } => {
                return Err(TransactionError::UnsupportedSignatureScheme { variant: *variant })
            }
        };

        if pub_keys.len() != signatures.len() {
            return Err(TransactionError::InvalidWitnessLength);
        }

        let txid = self.tx_hash();
        let msg = secp256k1_zkp::Message::from_slice(&txid[..]).expect("txid has right length");

        for (pk, signature) in pub_keys.iter().zip(signatures) {
            if secp256k1_zkp::global::SECP256K1
                .verify_schnorr(signature, &msg, &pk.x_only_public_key().0)
                .is_err()
            {
                return Err(TransactionError::InvalidSignature {
                    tx: self.consensus_encode_to_hex(),
                    hash: self.tx_hash().consensus_encode_to_hex(),
                    sig: signature.consensus_encode_to_hex(),
                    key: pk.consensus_encode_to_hex(),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub enum TransactionSignature {
    NaiveMultisig(Vec<schnorr::Signature>),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Error, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum TransactionError {
    #[error("The transaction is unbalanced (in={inputs}, out={outputs}, fee={fee})")]
    UnbalancedTransaction {
        inputs: Amount,
        outputs: Amount,
        fee: Amount,
    },
    #[error("The transaction's signature is invalid: tx={tx}, hash={hash}, sig={sig}, key={key}")]
    InvalidSignature {
        tx: String,
        hash: String,
        sig: String,
        key: String,
    },
    #[error("The transaction's signature scheme is not supported: variant={variant}")]
    UnsupportedSignatureScheme { variant: u64 },
    #[error("The transaction did not have the correct number of signatures")]
    InvalidWitnessLength,
    #[error("The transaction had an invalid input")]
    Input(DynInputError),
    #[error("The transaction had an invalid output")]
    Output(DynOutputError),
}

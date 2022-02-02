use crate::api::FederationApi;
use crate::PegInProofError;
use bitcoin::Address;
use db::PegInKey;
use minimint::config::FeeConsensus;
use minimint::modules::wallet;
use minimint::modules::wallet::tweakable::Tweakable;
use minimint::modules::wallet::txoproof::{PegInProof, TxOutProof};
use minimint::modules::wallet::PegOut;
use minimint_api::db::batch::BatchTx;
use minimint_api::db::{Database, RawDatabase};
use minimint_api::Amount;
use miniscript::DescriptorTrait;
use rand::{CryptoRng, RngCore};
use secp256k1_zkp::schnorrsig::KeyPair;
use std::sync::Arc;
use thiserror::Error;
use tracing::debug;

mod db;

/// Federation module client for the Wallet module. It can both create transaction inputs and
/// outputs of the wallet (on-chain) type.
pub struct WalletClient {
    pub db: Arc<dyn RawDatabase>,
    pub cfg: wallet::config::WalletClientConfig,
    pub api: Arc<dyn FederationApi>,
    pub secp: secp256k1_zkp::Secp256k1<secp256k1_zkp::All>,
    // TODO: find better way to handle fees
    pub fee_consensus: FeeConsensus,
}

impl WalletClient {
    pub fn get_new_pegin_address<R: RngCore + CryptoRng>(
        &self,
        mut batch: BatchTx<'_>,
        mut rng: R,
    ) -> Address {
        let peg_in_sec_key = secp256k1_zkp::schnorrsig::KeyPair::new(&self.secp, &mut rng);
        let peg_in_pub_key =
            secp256k1_zkp::schnorrsig::PublicKey::from_keypair(&self.secp, &peg_in_sec_key);

        // TODO: check at startup that no bare descriptor is used in config
        // TODO: check if there are other failure cases
        let script = self
            .cfg
            .peg_in_descriptor
            .tweak(&peg_in_pub_key, &self.secp)
            .script_pubkey();
        debug!("Peg-in script: {}", script);
        let address = Address::from_script(&script, self.cfg.network)
            .expect("Script from descriptor should have an address");

        batch.append_insert_new(
            PegInKey {
                peg_in_script: script,
            },
            peg_in_sec_key.serialize_secret(),
        );

        batch.commit();
        address
    }

    pub fn create_pegin_input(
        &self,
        txout_proof: TxOutProof,
        btc_transaction: bitcoin::Transaction,
    ) -> Result<(KeyPair, PegInProof)> {
        let (output_idx, secret_tweak_key_bytes) = btc_transaction
            .output
            .iter()
            .enumerate()
            .find_map(|(idx, out)| {
                debug!("Output script: {}", out.script_pubkey);
                self.db
                    .get_value::<_, [u8; 32]>(&PegInKey {
                        peg_in_script: out.script_pubkey.clone(),
                    })
                    .expect("DB error")
                    .map(|tweak_secret| (idx, tweak_secret))
            })
            .ok_or(WalletClientError::NoMatchingPegInFound)?;
        let secret_tweak_key = secp256k1_zkp::schnorrsig::KeyPair::from_seckey_slice(
            &self.secp,
            &secret_tweak_key_bytes,
        )
        .expect("sec key was generated and saved by us");
        let public_tweak_key =
            secp256k1_zkp::schnorrsig::PublicKey::from_keypair(&self.secp, &secret_tweak_key);

        let peg_in_proof = PegInProof::new(
            txout_proof,
            btc_transaction,
            output_idx as u32,
            public_tweak_key,
        )
        .map_err(WalletClientError::PegInProofError)?;

        peg_in_proof
            .verify(&self.secp, &self.cfg.peg_in_descriptor)
            .map_err(WalletClientError::PegInProofError)?;
        let sats = peg_in_proof.tx_output().value;

        let amount = Amount::from_sat(sats).saturating_sub(self.fee_consensus.fee_peg_in_abs);
        if amount == Amount::ZERO {
            return Err(WalletClientError::PegInAmountTooSmall);
        }

        // TODO: invalidate tweak keys on finalization

        Ok((secret_tweak_key, peg_in_proof))
    }

    pub fn create_pegout_output(
        &self,
        amount: bitcoin::Amount,
        recipient: bitcoin::Address,
    ) -> PegOut {
        PegOut { recipient, amount }
    }
}

type Result<T> = std::result::Result<T, WalletClientError>;

#[derive(Error, Debug)]
pub enum WalletClientError {
    #[error("Could not find an ongoing matching peg-in")]
    NoMatchingPegInFound,
    #[error("Peg-in amount must be greater than peg-in fee")]
    PegInAmountTooSmall,
    #[error("Inconsistent peg-in proof: {0}")]
    PegInProofError(PegInProofError),
}

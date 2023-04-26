use std::sync::Arc;

use bitcoin::{Address, KeyPair};
use db::PegInKey;
use fedimint_core::api::{GlobalFederationApi, OutputOutcomeError};
use fedimint_core::core::client::ClientModule;
use fedimint_core::core::Decoder;
use fedimint_core::db::DatabaseTransaction;
use fedimint_core::module::{ModuleCommon, TransactionItemAmount};
use fedimint_core::txoproof::TxOutProof;
use fedimint_core::Amount;
use fedimint_wallet_client::WalletClientModule;
use rand::{CryptoRng, RngCore};
use thiserror::Error;
use tracing::debug;

use crate::modules::wallet::config::WalletClientConfig;
use crate::modules::wallet::tweakable::Tweakable;
use crate::modules::wallet::txoproof::{PegInProof, PegInProofError};
use crate::modules::wallet::{WalletInput, WalletModuleTypes, WalletOutput, WalletOutputOutcome};
use crate::utils::ClientContext;
use crate::MemberError;

pub mod db;

/// Federation module client for the Wallet module. It can both create
/// transaction inputs and outputs of the wallet (on-chain) type.
#[derive(Debug)]
pub struct WalletClient {
    pub config: WalletClientConfig,
    pub context: Arc<ClientContext>,
}

impl ClientModule for WalletClient {
    const KIND: &'static str = "wallet";
    type Module = WalletModuleTypes;

    fn decoder(&self) -> Decoder {
        WalletModuleTypes::decoder()
    }

    fn input_amount(&self, input: &WalletInput) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: Amount::from_sats(input.tx_output().value),
            fee: self.config.fee_consensus.peg_in_abs,
        }
    }

    fn output_amount(&self, output: &WalletOutput) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: output.amount().into(),
            fee: self.config.fee_consensus.peg_out_abs,
        }
    }
}

impl WalletClient {
    /// Returns a bitcoin-address derived from the federations peg-in-descriptor
    /// and a random tweak
    ///
    /// This function will create a public/secret [keypair](bitcoin::KeyPair).
    /// The public key is used to tweak the federations peg-in-descriptor
    /// resulting in a bitcoin script. Both script and keypair are stored in the
    /// DB by using the script as part of the key and the keypair as the
    /// value. Even though only the public-key is used to tweak
    /// the descriptor, the secret-key is needed to prove that one actually
    /// created the tweak to be able to claim the funds and
    /// prevent front-running by a malicious  federation member
    /// The returned bitcoin-address is derived from the script. Thus sending
    /// bitcoin to that address will result in a transaction containing the
    /// scripts public-key in at least one of it's outpoints.
    pub async fn get_new_pegin_address<'a, R: RngCore + CryptoRng>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        mut rng: R,
    ) -> Address {
        let peg_in_keypair = bitcoin::KeyPair::new(&self.context.secp, &mut rng);
        let peg_in_pub_key = secp256k1_zkp::XOnlyPublicKey::from_keypair(&peg_in_keypair).0;

        // TODO: check at startup that no bare descriptor is used in config
        // TODO: check if there are other failure cases
        let script = self
            .config
            .peg_in_descriptor
            .tweak(&peg_in_pub_key, &self.context.secp)
            .script_pubkey();
        debug!(?script);
        let address = Address::from_script(&script, self.config.network)
            .expect("Script from descriptor should have an address");

        dbtx.insert_new_entry(
            &PegInKey {
                peg_in_script: script,
            },
            &peg_in_keypair.secret_bytes(),
        )
        .await;

        address
    }

    pub async fn create_pegin_input(
        &self,
        txout_proof: TxOutProof,
        btc_transaction: bitcoin::Transaction,
    ) -> Result<(KeyPair, PegInProof)> {
        let output_function = || async {
            for (idx, out) in btc_transaction.output.iter().enumerate() {
                debug!(output_script = ?out.script_pubkey);
                let result = self
                    .context
                    .db
                    .begin_transaction()
                    .await
                    .get_value(&PegInKey {
                        peg_in_script: out.script_pubkey.clone(),
                    })
                    .await
                    .map(|tweak_secret| (idx, tweak_secret));
                if result.is_some() {
                    return result;
                }
            }
            None
        };

        let (output_idx, secret_tweak_key_bytes) = output_function()
            .await
            .ok_or(WalletClientError::NoMatchingPegInFound)?;

        let secret_tweak_key =
            bitcoin::KeyPair::from_seckey_slice(&self.context.secp, &secret_tweak_key_bytes)
                .expect("sec key was generated and saved by us");

        let peg_in_proof = PegInProof::new(
            txout_proof,
            btc_transaction,
            output_idx as u32,
            secret_tweak_key.x_only_public_key().0,
        )
        .map_err(WalletClientError::PegInProofError)?;

        peg_in_proof
            .verify(&self.context.secp, &self.config.peg_in_descriptor)
            .map_err(WalletClientError::PegInProofError)?;

        let amount = Amount::from_sats(peg_in_proof.tx_output().value)
            .saturating_sub(self.config.fee_consensus.peg_in_abs);
        if amount == Amount::ZERO {
            return Err(WalletClientError::PegInAmountTooSmall);
        }

        // TODO: invalidate tweak keys on finalization

        Ok((secret_tweak_key, peg_in_proof))
    }

    pub async fn await_peg_out_outcome(
        &self,
        out_point: fedimint_core::OutPoint,
    ) -> Result<bitcoin::Txid> {
        // TODO: define timeout centrally
        let timeout = std::time::Duration::from_secs(15);
        let outcome = self
            .context
            .api
            .await_output_outcome::<WalletOutputOutcome>(
                out_point,
                timeout,
                &<WalletClientModule as fedimint_client::module::ClientModule>::decoder(),
            )
            .await?;
        Ok(outcome.0)
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
    #[error("Output outcome error: {0}")]
    OutputOutcomeError(#[from] OutputOutcomeError),
    #[error("Mint API error: {0}")]
    ApiError(#[from] MemberError),
}

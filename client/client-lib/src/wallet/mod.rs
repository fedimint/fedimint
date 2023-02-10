use std::sync::Arc;

use bitcoin::Address;
use bitcoin::KeyPair;
use db::PegInKey;
use fedimint_api::core::client::ClientModule;
use fedimint_api::db::DatabaseTransaction;
use fedimint_api::module::TransactionItemAmount;
use fedimint_api::{Amount, ServerModule};
use fedimint_core::api::GlobalFederationApi;
use fedimint_core::api::OutputOutcomeError;
use rand::{CryptoRng, RngCore};
use thiserror::Error;
use tracing::debug;

use crate::modules::wallet::common::WalletDecoder;
use crate::modules::wallet::config::WalletClientConfig;
use crate::modules::wallet::tweakable::Tweakable;
use crate::modules::wallet::txoproof::{PegInProof, PegInProofError, TxOutProof};
use crate::modules::wallet::WalletInput;
use crate::modules::wallet::WalletOutput;
use crate::modules::wallet::{Wallet, WalletOutputOutcome};
use crate::outcome::legacy::OutputOutcome;
use crate::utils::ClientContext;
use crate::MemberError;

pub mod db;

/// Federation module client for the Wallet module. It can both create transaction inputs and
/// outputs of the wallet (on-chain) type.
#[derive(Debug)]
pub struct WalletClient {
    pub config: WalletClientConfig,
    pub context: Arc<ClientContext>,
}

impl ClientModule for WalletClient {
    const KIND: &'static str = "wallet";
    type Decoder = <Wallet as ServerModule>::Decoder;
    type Module = Wallet;

    fn decoder(&self) -> Self::Decoder {
        WalletDecoder
    }

    fn input_amount(&self, input: &WalletInput) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: Amount::from_sats(input.tx_output().value),
            fee: self.config.fee_consensus.peg_in_abs,
        }
    }

    fn output_amount(&self, output: &WalletOutput) -> TransactionItemAmount {
        TransactionItemAmount {
            amount: (output.amount + output.fees.amount()).into(),
            fee: self.config.fee_consensus.peg_out_abs,
        }
    }
}

impl WalletClient {
    /// Returns a bitcoin-address derived from the federations peg-in-descriptor and a random tweak
    ///
    /// This function will create a public/secret [keypair](bitcoin::KeyPair). The public key is used to tweak the
    /// federations peg-in-descriptor resulting in a bitcoin script. Both script and keypair are stored in the DB
    /// by using the script as part of the key and the keypair as the value. Even though only the public-key is used to tweak
    /// the descriptor, the secret-key is needed to prove that one actually created the tweak to be able to claim the funds and
    /// prevent front-running by a malicious  federation member
    /// The returned bitcoin-address is derived from the script. Thus sending bitcoin to that address will result in a
    /// transaction containing the scripts public-key in at least one of it's outpoints.
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
        .await
        .expect("DB Error");

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
                    .expect("DB error")
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
        out_point: fedimint_api::OutPoint,
    ) -> Result<bitcoin::Txid> {
        // TODO: define timeout centrally
        let timeout = std::time::Duration::from_secs(15);
        let outcome: WalletOutputOutcome = self
            .context
            .api
            .await_output_outcome::<OutputOutcome>(out_point, timeout, &self.context.decoders)
            .await?
            .try_into_variant()?;
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    use bitcoin::hashes::sha256;
    use bitcoin::{Address, Txid};
    use bitcoin_hashes::Hash;
    use fedimint_api::config::ConfigGenParams;
    use fedimint_api::core::{
        DynOutputOutcome, ModuleInstanceId, LEGACY_HARDCODED_INSTANCE_ID_WALLET,
    };
    use fedimint_api::db::mem_impl::MemDatabase;
    use fedimint_api::db::Database;
    use fedimint_api::module::registry::ModuleDecoderRegistry;
    use fedimint_api::task::TaskGroup;
    use fedimint_api::{Feerate, OutPoint, TransactionId};
    use fedimint_core::outcome::{SerdeOutputOutcome, TransactionStatus};
    use fedimint_testing::btc::bitcoind::{FakeBitcoindRpc, FakeBitcoindRpcController};
    use fedimint_testing::FakeFed;
    use tokio::sync::Mutex;

    use crate::api::fake::FederationApiFaker;
    use crate::modules::wallet::common::WalletDecoder;
    use crate::modules::wallet::config::WalletClientConfig;
    use crate::modules::wallet::{
        PegOut, PegOutFees, Wallet, WalletGen, WalletGenParams, WalletOutput, WalletOutputOutcome,
    };
    use crate::wallet::WalletClient;
    use crate::{module_decode_stubs, ClientContext};

    type Fed = FakeFed<Wallet>;
    type SharedFed = Arc<tokio::sync::Mutex<Fed>>;

    #[derive(Debug)]
    struct FakeApi {
        // for later use once wallet outcomes are implemented
        _mint: SharedFed,
    }

    pub async fn make_test_mint_fed(
        module_id: ModuleInstanceId,
        fed: Arc<Mutex<FakeFed<Wallet>>>,
    ) -> FederationApiFaker<tokio::sync::Mutex<FakeFed<Wallet>>> {
        let members = fed
            .lock()
            .await
            .members
            .iter()
            .map(|(peer_id, _, _, _)| *peer_id)
            .collect();
        FederationApiFaker::new(fed, members).with(
            "/fetch_transaction",
            move |_mint: Arc<Mutex<FakeFed<Wallet>>>, _tx: TransactionId| async move {
                Ok(TransactionStatus::Accepted {
                    epoch: 0,
                    outputs: vec![SerdeOutputOutcome::from(&DynOutputOutcome::from_typed(
                        module_id,
                        WalletOutputOutcome(Txid::from_slice([0; 32].as_slice()).unwrap()),
                    ))],
                })
            },
        )
    }

    async fn new_mint_and_client(
        task_group: &mut TaskGroup,
    ) -> (
        Arc<tokio::sync::Mutex<Fed>>,
        WalletClientConfig,
        ClientContext,
        FakeBitcoindRpcController,
    ) {
        let btc_rpc = FakeBitcoindRpc::new();
        let btc_rpc_controller = btc_rpc.controller();

        let module_id = LEGACY_HARDCODED_INSTANCE_ID_WALLET;
        let fed = Arc::new(tokio::sync::Mutex::new(
            FakeFed::<Wallet>::new(
                4,
                move |cfg, db| {
                    let mut task_group = task_group.clone();
                    let btc_rpc_clone = btc_rpc.clone();
                    async move {
                        Ok(Wallet::new_with_bitcoind(
                            cfg.to_typed().unwrap(),
                            db.new_isolated(module_id),
                            btc_rpc_clone.clone().into(),
                            &mut task_group,
                        )
                        .await?)
                    }
                },
                &ConfigGenParams::new().attach(WalletGenParams {
                    network: bitcoin::network::constants::Network::Regtest,
                    finality_delay: 10,
                }),
                &WalletGen,
                module_id,
            )
            .await
            .unwrap(),
        ));

        let api = make_test_mint_fed(module_id, fed.clone()).await;
        let client_config = fed.lock().await.client_cfg().clone();

        let client = ClientContext {
            decoders: ModuleDecoderRegistry::from_iter([(module_id, WalletDecoder.into())]),
            module_gens: Default::default(),
            db: Database::new(MemDatabase::new(), module_decode_stubs()),
            api: api.into(),
            secp: secp256k1_zkp::Secp256k1::new(),
        };

        (
            fed,
            client_config.cast().unwrap(),
            client,
            btc_rpc_controller,
        )
    }

    #[test_log::test(tokio::test)]
    async fn create_output() {
        let mut task_group = TaskGroup::new();
        let (fed, client_config, client_context, btc_rpc) =
            new_mint_and_client(&mut task_group).await;
        let _client = WalletClient {
            config: client_config,
            context: Arc::new(client_context),
        };

        // Set fees low forever
        btc_rpc
            .set_fee_rate(Some(Feerate { sats_per_kvb: 0 }))
            .await;

        // generate fake UTXO
        fed.lock().await.generate_fake_utxo().await;

        let addr = Address::from_str("msFGPqHVk8rbARMd69FfGYxwcboZLemdBi").unwrap();
        let amount = bitcoin::Amount::from_sat(42000);

        let out_point = OutPoint {
            txid: sha256::Hash::hash(b"txid").into(),
            out_idx: 0,
        };
        let output = PegOut {
            recipient: addr.clone(),
            amount,
            fees: PegOutFees {
                fee_rate: Feerate { sats_per_kvb: 0 },
                total_weight: 0,
            },
        };

        // agree on output
        btc_rpc.set_block_height(100).await;
        fed.lock()
            .await
            .consensus_round(&[], &[(out_point, WalletOutput(output))])
            .await;

        // begin pegout
        btc_rpc.set_block_height(201).await;
        fed.lock().await.consensus_round(&[], &[]).await;

        // combine signatures
        fed.lock().await.consensus_round(&[], &[]).await;

        // FIXME: find out why these extra rounds are necessary (needs tracing improvement), increases latency only negligibly
        fed.lock().await.consensus_round(&[], &[]).await;
        fed.lock().await.consensus_round(&[], &[]).await;

        // wait for broadcast
        fedimint_api::task::sleep(Duration::from_secs(12)).await;
        assert!(btc_rpc.is_btc_sent_to(amount, addr).await);

        let wallet_value = fed
            .lock()
            .await
            .fetch_from_all(|wallet, db, module_instance_id| async {
                wallet
                    .get_wallet_value(
                        &mut db
                            .begin_transaction()
                            .await
                            .with_module_prefix(*module_instance_id),
                    )
                    .await
            })
            .await;
        assert_eq!(wallet_value, bitcoin::Amount::from_sat(0));

        // test change recognition, wallet should hold some sats
        btc_rpc.add_pending_tx_to_block(202).await;
        btc_rpc.set_block_height(301).await;
        fed.lock().await.consensus_round(&[], &[]).await;

        let wallet_value = fed
            .lock()
            .await
            .fetch_from_all(|wallet, db, module_instance_id| async {
                wallet
                    .get_wallet_value(
                        &mut db
                            .begin_transaction()
                            .await
                            .with_module_prefix(*module_instance_id),
                    )
                    .await
            })
            .await;
        assert!(wallet_value > bitcoin::Amount::from_sat(0));
    }
}

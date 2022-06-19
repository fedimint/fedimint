use crate::BorrowedClientContext;
use bitcoin::Address;
use db::PegInKey;
use minimint_api::db::batch::BatchTx;
use minimint_api::Amount;
use minimint_core::config::FeeConsensus;
use minimint_core::modules::wallet::config::WalletClientConfig;
use minimint_core::modules::wallet::tweakable::Tweakable;
use minimint_core::modules::wallet::txoproof::{PegInProof, PegInProofError, TxOutProof};
use minimint_core::modules::wallet::PegOut;
use miniscript::DescriptorTrait;
use rand::{CryptoRng, RngCore};
use secp256k1_zkp::schnorrsig::KeyPair;
use thiserror::Error;
use tracing::debug;

mod db;

/// Federation module client for the Wallet module. It can both create transaction inputs and
/// outputs of the wallet (on-chain) type.
pub struct WalletClient<'c> {
    pub context: BorrowedClientContext<'c, WalletClientConfig>,
    pub fee_consensus: FeeConsensus,
}

impl<'c> WalletClient<'c> {
    pub fn get_new_pegin_address<R: RngCore + CryptoRng>(
        &self,
        mut batch: BatchTx<'_>,
        mut rng: R,
    ) -> Address {
        let peg_in_sec_key = secp256k1_zkp::schnorrsig::KeyPair::new(self.context.secp, &mut rng);
        let peg_in_pub_key =
            secp256k1_zkp::schnorrsig::PublicKey::from_keypair(self.context.secp, &peg_in_sec_key);

        // TODO: check at startup that no bare descriptor is used in config
        // TODO: check if there are other failure cases
        let script = self
            .context
            .config
            .peg_in_descriptor
            .tweak(&peg_in_pub_key, self.context.secp)
            .script_pubkey();
        debug!(?script);
        let address = Address::from_script(&script, self.context.config.network)
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
                debug!(output_script = ?out.script_pubkey);
                self.context
                    .db
                    .get_value(&PegInKey {
                        peg_in_script: out.script_pubkey.clone(),
                    })
                    .expect("DB error")
                    .map(|tweak_secret| (idx, tweak_secret))
            })
            .ok_or(WalletClientError::NoMatchingPegInFound)?;
        let secret_tweak_key = secp256k1_zkp::schnorrsig::KeyPair::from_seckey_slice(
            self.context.secp,
            &secret_tweak_key_bytes,
        )
        .expect("sec key was generated and saved by us");
        let public_tweak_key = secp256k1_zkp::schnorrsig::PublicKey::from_keypair(
            self.context.secp,
            &secret_tweak_key,
        );

        let peg_in_proof = PegInProof::new(
            txout_proof,
            btc_transaction,
            output_idx as u32,
            public_tweak_key,
        )
        .map_err(WalletClientError::PegInProofError)?;

        peg_in_proof
            .verify(self.context.secp, &self.context.config.peg_in_descriptor)
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

#[cfg(test)]
mod tests {
    use crate::api::FederationApi;
    use crate::wallet::WalletClient;
    use crate::OwnedClientContext;
    use async_trait::async_trait;
    use bitcoin::Address;

    use minimint_api::db::mem_impl::MemDatabase;
    use minimint_api::module::testing::FakeFed;
    use minimint_api::{Amount, OutPoint, TransactionId};
    use minimint_core::config::FeeConsensus;
    use minimint_core::modules::ln::contracts::incoming::IncomingContractOffer;
    use minimint_core::modules::ln::contracts::ContractId;
    use minimint_core::modules::ln::ContractAccount;
    use minimint_core::modules::wallet::bitcoind::test::{
        FakeBitcoindRpc, FakeBitcoindRpcController,
    };
    use minimint_core::modules::wallet::config::WalletClientConfig;
    use minimint_core::modules::wallet::db::UTXOKey;
    use minimint_core::modules::wallet::{SpendableUTXO, Wallet};
    use minimint_core::outcome::{OutputOutcome, TransactionStatus};
    use minimint_core::transaction::Transaction;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    type Fed = FakeFed<Wallet, WalletClientConfig>;
    type SharedFed = Arc<tokio::sync::Mutex<Fed>>;

    struct FakeApi {
        // for later use once wallet outcomes are implemented
        _mint: SharedFed,
    }

    #[async_trait]
    impl FederationApi for FakeApi {
        async fn fetch_tx_outcome(
            &self,
            _tx: TransactionId,
        ) -> crate::api::Result<TransactionStatus> {
            Ok(TransactionStatus::Accepted {
                epoch: 0,
                outputs: vec![OutputOutcome::Wallet(())],
            })
        }

        async fn submit_transaction(&self, _tx: Transaction) -> crate::api::Result<TransactionId> {
            unimplemented!()
        }

        async fn fetch_contract(
            &self,
            _contract: ContractId,
        ) -> crate::api::Result<ContractAccount> {
            unimplemented!()
        }

        async fn fetch_consensus_block_height(&self) -> crate::api::Result<u64> {
            unimplemented!()
        }

        async fn fetch_offer(
            &self,
            _payment_hash: bitcoin::hashes::sha256::Hash,
        ) -> crate::api::Result<IncomingContractOffer> {
            unimplemented!();
        }
    }

    async fn new_mint_and_client() -> (
        Arc<tokio::sync::Mutex<Fed>>,
        OwnedClientContext<WalletClientConfig>,
        FakeBitcoindRpcController,
    ) {
        let btc_rpc = FakeBitcoindRpc::new();
        let btc_rpc_controller = btc_rpc.controller();

        let fed = Arc::new(tokio::sync::Mutex::new(
            FakeFed::<Wallet, WalletClientConfig>::new(
                4,
                1,
                move |cfg, db| {
                    let btc_rpc_clone = btc_rpc.clone();
                    async move {
                        Wallet::new_with_bitcoind(cfg, Arc::new(db), || {
                            Box::new(btc_rpc_clone.clone())
                        })
                        .await
                        .unwrap()
                    }
                },
                &(),
            )
            .await,
        ));

        let api = FakeApi { _mint: fed.clone() };

        let client = OwnedClientContext {
            config: fed.lock().await.client_cfg().clone(),
            db: Box::new(MemDatabase::new()),
            api: Box::new(api),
            secp: secp256k1_zkp::Secp256k1::new(),
        };

        (fed, client, btc_rpc_controller)
    }

    #[test_log::test(tokio::test)]
    async fn create_output() {
        let (fed, client_context, btc_rpc) = new_mint_and_client().await;
        let client = WalletClient {
            context: client_context.borrow_with_module_config(|x| x),
            fee_consensus: FeeConsensus {
                fee_coin_spend_abs: Amount::ZERO,
                fee_peg_in_abs: Amount::ZERO,
                fee_coin_issuance_abs: Amount::ZERO,
                fee_peg_out_abs: Amount::ZERO,
                fee_contract_input: Amount::ZERO,
                fee_contract_output: Amount::ZERO,
            },
        };

        // generate fake UTXO
        fed.lock().await.patch_dbs(|db| {
            let out_point = bitcoin::OutPoint::default();
            let tweak = [42; 32];
            let utxo = SpendableUTXO {
                tweak,
                amount: bitcoin::Amount::from_sat(48000),
            };

            db.insert_entry(&UTXOKey(out_point), &utxo).unwrap();
        });

        let addr = Address::from_str("msFGPqHVk8rbARMd69FfGYxwcboZLemdBi").unwrap();
        let amount = bitcoin::Amount::from_sat(42000);

        let out_point = OutPoint {
            txid: Default::default(),
            out_idx: 0,
        };
        let output = client.create_pegout_output(amount, addr.clone());

        // agree on output
        btc_rpc.set_block_height(100).await;
        fed.lock()
            .await
            .consensus_round(&[], &[(out_point, output)])
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
        minimint_api::task::sleep(Duration::from_secs(12)).await;
        assert!(btc_rpc.is_btc_sent_to(amount, addr).await);

        let wallet_value = fed
            .lock()
            .await
            .fetch_from_all(|wallet| wallet.get_wallet_value());
        assert_eq!(wallet_value, bitcoin::Amount::from_sat(0));

        // test change recognition, wallet should hold some sats
        btc_rpc.add_pending_tx_to_block(202).await;
        btc_rpc.set_block_height(301).await;
        fed.lock().await.consensus_round(&[], &[]).await;

        let wallet_value = fed
            .lock()
            .await
            .fetch_from_all(|wallet| wallet.get_wallet_value());
        assert!(wallet_value > bitcoin::Amount::from_sat(0));
    }
}

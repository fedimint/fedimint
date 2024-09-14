#![deny(clippy::pedantic)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::single_match_else)]
#![allow(clippy::too_many_lines)]

pub mod db;

use std::cmp::min;
use std::collections::BTreeMap;

use anyhow::{Context, bail, ensure};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::psbt::Input;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, Psbt, Sequence, Transaction, TxIn, TxOut, Txid};
use common::config::WalletConfigConsensus;
use common::{
    DepositRange, WalletCommonInit, WalletConsensusItem, WalletInput, WalletModuleTypes,
    WalletOutput, WalletOutputOutcome,
};
use db::{
    Deposit, DepositKey, DepositPrefix, FederationWalletKey, FederationWalletPrefix, SignaturesKey,
    SignaturesTxidPrefix, SpentDepositKey, TransactionLogIndexKey,
};
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiVersion, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta,
    ModuleConsensusVersion, ModuleInit, SupportedModuleApiVersions, TransactionItemAmounts,
    api_endpoint,
};
#[cfg(not(target_family = "wasm"))]
use fedimint_core::task::TaskGroup;
use fedimint_core::task::sleep;
use fedimint_core::{InPoint, NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send, util};
use fedimint_logging::LOG_MODULE_WALLETV2;
use fedimint_server_core::bitcoin_rpc::ServerBitcoinRpcMonitor;
use fedimint_server_core::config::{PeerHandleOps, PeerHandleOpsExt};
use fedimint_server_core::{
    ConfigGenModuleArgs, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
pub use fedimint_walletv2_common as common;
use fedimint_walletv2_common::config::{
    FeeConsensus, WalletClientConfig, WalletConfig, WalletConfigPrivate,
};
use fedimint_walletv2_common::endpoint_constants::{
    CONSENSUS_BLOCK_COUNT_ENDPOINT, CONSENSUS_FEERATE_ENDPOINT, DEPOSIT_RANGE_ENDPOINT,
    FEDERATION_WALLET_ENDPOINT, PENDING_TRANSACTION_CHAIN_ENDPOINT, RECEIVE_FEE_ENDPOINT,
    SEND_FEE_ENDPOINT, TRANSACTION_CHAIN_ENDPOINT, TRANSACTION_ID_ENDPOINT,
};
use fedimint_walletv2_common::{
    FederationWallet, MODULE_CONSENSUS_VERSION, TransactionInfo, WalletInputError,
    WalletOutputError, descriptor, is_valid_script, tweak_public_key,
};
use futures::StreamExt;
use miniscript::descriptor::Wsh;
use miniscript::psbt::PsbtExt;
use rand::rngs::OsRng;
use secp256k1::ecdsa::Signature;
use secp256k1::{PublicKey, Scalar, SecretKey};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::db::{
    BlockCountVoteKey, BlockCountVotePrefix, FeeRateVoteKey, FeeRateVotePrefix,
    PendingTransactionKey, PendingTransactionPrefix, TransactionLogKey, TransactionLogPrefix,
    UnsignedTransactionKey, UnsignedTransactionPrefix,
};

/// Number of confirmations required for a transaction to be considered as
/// confirmed by the federation.
pub const FINALITY_DELAY: u64 = 6;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Encodable, Decodable)]
pub struct TransactionLog {
    pub transaction: Transaction,
    pub input: Amount,
    pub output: Amount,
    pub vbytes: u64,
    pub fee: Amount,
    pub created: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Encodable, Decodable)]
pub struct UnsignedTransaction {
    pub transaction: Transaction,
    pub spent_tx_outs: Vec<SpentTxOut>,
    pub vbytes: u64,
    pub fee: Amount,
    pub created: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Encodable, Decodable)]
pub struct PendingTransaction {
    pub transaction: Transaction,
    pub vbytes: u64,
    pub fee: Amount,
    pub created: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct SpentTxOut {
    pub value: Amount,
    pub tweak: Option<sha256::Hash>,
}

#[derive(Debug, Clone)]
pub struct WalletInit;

impl ModuleInit for WalletInit {
    type Common = WalletCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        todo!()
    }
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleInit for WalletInit {
    type Module = Wallet;

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(
            (CORE_CONSENSUS_VERSION.major, CORE_CONSENSUS_VERSION.minor),
            (
                MODULE_CONSENSUS_VERSION.major,
                MODULE_CONSENSUS_VERSION.minor,
            ),
            &[(0, 1)],
        )
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(Wallet::new(
            args.cfg().to_typed()?,
            args.db(),
            args.task_group(),
            args.server_bitcoin_rpc_monitor(),
        ))
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let fee_consensus = FeeConsensus::new(0).expect("Relative fee is within range");

        let bitcoin_sks = peers
            .iter()
            .map(|peer| (*peer, SecretKey::new(&mut secp256k1::rand::thread_rng())))
            .collect::<BTreeMap<PeerId, SecretKey>>();

        let bitcoin_pks = bitcoin_sks
            .iter()
            .map(|(peer, sk)| (*peer, sk.public_key(secp256k1::SECP256K1)))
            .collect::<BTreeMap<PeerId, PublicKey>>();

        bitcoin_sks
            .into_iter()
            .map(|(peer, bitcoin_sk)| {
                let config = WalletConfig {
                    private: WalletConfigPrivate { bitcoin_sk },
                    consensus: WalletConfigConsensus::new(
                        bitcoin_pks.clone(),
                        fee_consensus.clone(),
                        args.network,
                    ),
                };

                (peer, config.to_erased())
            })
            .collect()
    }

    async fn distributed_gen(
        &self,
        peers: &(dyn PeerHandleOps + Send + Sync),
        args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        let fee_consensus = FeeConsensus::new(0).expect("Relative fee is within range");

        let (bitcoin_sk, bitcoin_pk) = secp256k1::generate_keypair(&mut OsRng);

        let bitcoin_pks: BTreeMap<PeerId, PublicKey> = peers
            .exchange_encodable(bitcoin_pk)
            .await?
            .into_iter()
            .collect();

        let config = WalletConfig {
            private: WalletConfigPrivate { bitcoin_sk },
            consensus: WalletConfigConsensus::new(bitcoin_pks, fee_consensus, args.network),
        };

        Ok(config.to_erased())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<WalletConfig>()?;

        ensure!(
            config
                .consensus
                .bitcoin_pks
                .get(identity)
                .ok_or(anyhow::anyhow!("No public key for our identity"))?
                == &config.private.bitcoin_sk.public_key(secp256k1::SECP256K1),
            "Bitcoin wallet private key doesn't match multisig pubkey"
        );

        Ok(())
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<WalletClientConfig> {
        let config = WalletConfigConsensus::from_erased(config)?;
        Ok(WalletClientConfig {
            bitcoin_pks: config.bitcoin_pks,
            dust_limit: config.dust_limit,
            fee_consensus: config.fee_consensus,
            network: config.network,
        })
    }
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Wallet {
    type Common = WalletModuleTypes;
    type Init = WalletInit;

    async fn consensus_proposal<'a>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<WalletConsensusItem> {
        let mut items = dbtx
            .find_by_prefix(&UnsignedTransactionPrefix)
            .await
            .map(|(key, unsigned_transaction)| {
                let signatures = self.sign_transaction(&unsigned_transaction);

                assert!(
                    self.verify_signatures(
                        &unsigned_transaction,
                        &signatures,
                        self.cfg.private.bitcoin_sk.public_key(secp256k1::SECP256K1)
                    )
                    .is_ok(),
                    "Our signatures failed verification against our private key"
                );

                WalletConsensusItem::Signatures(key.0, signatures)
            })
            .collect::<Vec<WalletConsensusItem>>()
            .await;

        if let Some(status) = self.btc_rpc.status() {
            assert_eq!(status.network, self.cfg.consensus.network);

            let consensus_block_count = self.consensus_block_count(dbtx).await;

            items.push(WalletConsensusItem::BlockCount(min(
                status.block_count.saturating_sub(FINALITY_DELAY),
                consensus_block_count + 5,
            )));

            items.push(WalletConsensusItem::Feerate(Some(
                status.fee_rate.sats_per_kvb,
            )));
        } else {
            // Bitcoin backend not connected, retract fee rate vote
            items.push(WalletConsensusItem::Feerate(None));
        }

        items
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: WalletConsensusItem,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        match consensus_item {
            WalletConsensusItem::BlockCount(block_count_vote) => {
                let current_vote = dbtx.get_value(&BlockCountVoteKey(peer)).await.unwrap_or(0);

                ensure!(
                    block_count_vote > current_vote,
                    "Block count vote is redundant"
                );

                let old_consensus_block_count = self.consensus_block_count(dbtx).await;

                dbtx.insert_entry(&BlockCountVoteKey(peer), &block_count_vote)
                    .await;

                let new_consensus_block_count = self.consensus_block_count(dbtx).await;

                assert!(old_consensus_block_count <= new_consensus_block_count);

                // We do not sync blocks that predate the federation itself.
                if old_consensus_block_count == 0 {
                    return Ok(());
                }

                // Our bitcoin backend needs to be synced for the following calls to the
                // get_block rpc to be safe for consensus.
                self.await_local_sync_to_block_count(new_consensus_block_count + FINALITY_DELAY)
                    .await;

                for height in old_consensus_block_count..new_consensus_block_count {
                    // Verify network matches (status should be available after sync)
                    if let Some(status) = self.btc_rpc.status() {
                        assert_eq!(status.network, self.cfg.consensus.network);
                    }

                    let block_hash = util::retry(
                        "get_block_hash",
                        util::backoff_util::background_backoff(),
                        || self.btc_rpc.get_block_hash(height),
                    )
                    .await
                    .expect("Bitcoind rpc to get_block_hash failed");

                    let block = util::retry(
                        "get_block",
                        util::backoff_util::background_backoff(),
                        || self.btc_rpc.get_block(&block_hash),
                    )
                    .await
                    .expect("Bitcoind rpc to get_block failed");

                    let pks_hash = self.cfg.consensus.bitcoin_pks.consensus_hash();

                    for transaction in block.txdata {
                        dbtx.remove_entry(&PendingTransactionKey(transaction.compute_txid()))
                            .await;

                        // We maintain an append-only log of valid P2WSH transaction
                        // outputs created since the federation was established.

                        for (vout, tx_out) in transaction.output.iter().enumerate() {
                            if is_valid_script(&tx_out.script_pubkey, &pks_hash)
                                && tx_out.script_pubkey.is_p2wsh()
                            {
                                let outpoint = bitcoin::OutPoint {
                                    txid: transaction.compute_txid(),
                                    vout: u32::try_from(vout).expect(
                                        "Bitcoin transaction has more then u32::MAX outputs",
                                    ),
                                };

                                let index = dbtx
                                    .find_by_prefix_sorted_descending(&DepositPrefix)
                                    .await
                                    .next()
                                    .await
                                    .map_or(0, |entry| entry.0.0 + 1);

                                dbtx.insert_new_entry(
                                    &DepositKey(index),
                                    &Deposit(outpoint, tx_out.clone()),
                                )
                                .await;
                            }
                        }
                    }
                }
            }
            WalletConsensusItem::Feerate(feerate) => {
                if Some(feerate) == dbtx.insert_entry(&FeeRateVoteKey(peer), &feerate).await {
                    bail!("Fee rate vote is redundant");
                }
            }
            WalletConsensusItem::Signatures(txid, signatures) => {
                let unsigned_transaction = dbtx
                    .get_value(&UnsignedTransactionKey(txid))
                    .await
                    .context("Unsigned transaction does not exist")?;

                self.verify_signatures(
                    &unsigned_transaction,
                    &signatures,
                    *self
                        .cfg
                        .consensus
                        .bitcoin_pks
                        .get(&peer)
                        .expect("Failed to get public key of peer {peer} from config"),
                )?;

                if dbtx
                    .insert_entry(&SignaturesKey(txid, peer), &signatures)
                    .await
                    .is_some()
                {
                    bail!("Already received valid signatures from this peer")
                }

                let signatures = dbtx
                    .find_by_prefix(&SignaturesTxidPrefix(txid))
                    .await
                    .map(|(key, signatures)| (key.1, signatures))
                    .collect::<BTreeMap<PeerId, Vec<Signature>>>()
                    .await;

                if signatures.len() == self.cfg.consensus.bitcoin_pks.to_num_peers().threshold() {
                    dbtx.remove_entry(&UnsignedTransactionKey(txid)).await;

                    let transaction = self.finalize_transaction(&unsigned_transaction, &signatures);

                    dbtx.insert_new_entry(
                        &PendingTransactionKey(txid),
                        &PendingTransaction {
                            transaction,
                            vbytes: unsigned_transaction.vbytes,
                            fee: unsigned_transaction.fee,
                            created: unsigned_transaction.created,
                        },
                    )
                    .await;
                }
            }
            WalletConsensusItem::Default { variant, .. } => {
                bail!("Received wallet consensus item with unknown variant {variant}");
            }
        }

        Ok(())
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b WalletInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, WalletInputError> {
        let input = input.ensure_v0_ref()?;

        if dbtx
            .insert_entry(&SpentDepositKey(input.deposit_index), &())
            .await
            .is_some()
        {
            return Err(WalletInputError::DepositAlreadySpent);
        }

        let Deposit(outpoint, tx_out) = dbtx
            .get_value(&DepositKey(input.deposit_index))
            .await
            .ok_or(WalletInputError::UnknownDepositIndex)?;

        if tx_out.script_pubkey
            != self
                .descriptor(Some(&input.tweak.consensus_hash()))
                .script_pubkey()
        {
            return Err(WalletInputError::WrongTweak);
        }

        let consensus_receive_fee = self
            .receive_fee(dbtx)
            .await
            .ok_or(WalletInputError::NoConsensusFeerateAvailable)?;

        // We allow for a higher fee such that a guardian could construct a CPFP
        // transaction. This is the last line of defense should the federations
        // transactions ever get stuck due to a critical failure of the feerate
        // estimation.
        if input.fee < consensus_receive_fee {
            return Err(WalletInputError::InsufficientTotalFee);
        }

        let deposit_value = tx_out
            .value
            .checked_sub(input.fee)
            .ok_or(WalletInputError::ArithmeticOverflow)?;

        let transaction_index = self.total_transactions(dbtx).await;
        let created = self.consensus_block_count(dbtx).await;

        if let Some(federation_wallet) = dbtx.remove_entry(&FederationWalletKey).await {
            let change_value = federation_wallet
                .value
                .checked_add(deposit_value)
                .ok_or(WalletInputError::ArithmeticOverflow)?;

            let transaction = Transaction {
                version: Version(2),
                lock_time: LockTime::ZERO,
                input: vec![
                    TxIn {
                        previous_output: bitcoin::OutPoint {
                            txid: federation_wallet.txid,
                            vout: 0,
                        },
                        script_sig: Default::default(),
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: bitcoin::Witness::new(),
                    },
                    TxIn {
                        previous_output: outpoint,
                        script_sig: Default::default(),
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: bitcoin::Witness::new(),
                    },
                ],
                output: vec![TxOut {
                    value: change_value,
                    script_pubkey: self.descriptor(None).script_pubkey(),
                }],
            };

            dbtx.insert_new_entry(
                &FederationWalletKey,
                &FederationWallet {
                    value: change_value,
                    txid: transaction.compute_txid(),
                },
            )
            .await;

            dbtx.insert_new_entry(
                &TransactionLogKey(transaction_index),
                &TransactionLog {
                    transaction: transaction.clone(),
                    input: federation_wallet.value,
                    output: change_value,
                    vbytes: self.cfg.consensus.receive_tx_vbytes,
                    fee: input.fee,
                    created,
                },
            )
            .await;

            dbtx.insert_new_entry(
                &UnsignedTransactionKey(transaction.compute_txid()),
                &UnsignedTransaction {
                    transaction,
                    spent_tx_outs: vec![
                        SpentTxOut {
                            value: federation_wallet.value,
                            tweak: None,
                        },
                        SpentTxOut {
                            value: tx_out.value,
                            tweak: Some(input.tweak.consensus_hash()),
                        },
                    ],
                    vbytes: self.cfg.consensus.receive_tx_vbytes,
                    fee: input.fee,
                    created,
                },
            )
            .await;
        } else {
            let transaction = Transaction {
                version: Version(2),
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: outpoint,
                    script_sig: Default::default(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: bitcoin::Witness::new(),
                }],
                output: vec![TxOut {
                    value: deposit_value,
                    script_pubkey: self.descriptor(None).script_pubkey(),
                }],
            };

            dbtx.insert_new_entry(
                &FederationWalletKey,
                &FederationWallet {
                    value: deposit_value,
                    txid: transaction.compute_txid(),
                },
            )
            .await;

            dbtx.insert_new_entry(
                &TransactionLogKey(transaction_index),
                &TransactionLog {
                    transaction: transaction.clone(),
                    input: bitcoin::Amount::ZERO,
                    output: deposit_value,
                    vbytes: self.cfg.consensus.receive_tx_vbytes,
                    fee: input.fee,
                    created,
                },
            )
            .await;

            dbtx.insert_new_entry(
                &UnsignedTransactionKey(transaction.compute_txid()),
                &UnsignedTransaction {
                    transaction,
                    spent_tx_outs: vec![SpentTxOut {
                        value: tx_out.value,
                        tweak: Some(input.tweak.consensus_hash()),
                    }],
                    vbytes: self.cfg.consensus.receive_tx_vbytes,
                    fee: input.fee,
                    created,
                },
            )
            .await;
        }

        let amount = deposit_value
            .to_sat()
            .checked_mul(1000)
            .map(fedimint_core::Amount::from_msats)
            .ok_or(WalletInputError::ArithmeticOverflow)?;

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(amount),
                fees: Amounts::new_bitcoin(self.cfg.consensus.fee_consensus.fee(amount)),
            },
            pub_key: input.tweak,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a WalletOutput,
        outpoint: OutPoint,
    ) -> Result<TransactionItemAmounts, WalletOutputError> {
        let output = output.ensure_v0_ref()?;

        if output.value < self.cfg.consensus.dust_limit {
            return Err(WalletOutputError::UnderDustLimit);
        }

        let federation_utxo = dbtx
            .remove_entry(&FederationWalletKey)
            .await
            .ok_or(WalletOutputError::NoFederationUTXO)?;

        let consensus_send_fee = self
            .send_fee(dbtx)
            .await
            .ok_or(WalletOutputError::NoConsensusFeerateAvailable)?;

        // We allow for a higher fee such that a guardian could construct a CPFP
        // transaction. This is the last line of defense should the federations
        // transactions ever get stuck due to a critical failure of the feerate
        // estimation.
        if output.fee < consensus_send_fee {
            return Err(WalletOutputError::InsufficicentTotalFee);
        }

        let output_value = output
            .value
            .checked_add(output.fee)
            .ok_or(WalletOutputError::ArithmeticOverflow)?;

        // The change is non-zero as it contains the fees taken by the federation
        let change_value = federation_utxo
            .value
            .checked_sub(output_value)
            .ok_or(WalletOutputError::ArithmeticOverflow)?;

        let transaction = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: federation_utxo.txid,
                    vout: 0,
                },
                script_sig: Default::default(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: change_value,
                    script_pubkey: self.descriptor(None).script_pubkey(),
                },
                TxOut {
                    value: output.value,
                    script_pubkey: output.destination.script_pubkey(),
                },
            ],
        };

        dbtx.insert_new_entry(
            &FederationWalletKey,
            &FederationWallet {
                value: change_value,
                txid: transaction.compute_txid(),
            },
        )
        .await;

        let index = self.total_transactions(dbtx).await;

        let created = self.consensus_block_count(dbtx).await;

        dbtx.insert_new_entry(
            &TransactionLogKey(index),
            &TransactionLog {
                transaction: transaction.clone(),
                input: federation_utxo.value,
                output: change_value,
                vbytes: self.cfg.consensus.send_tx_vbytes,
                fee: output.fee,
                created,
            },
        )
        .await;

        dbtx.insert_new_entry(&TransactionLogIndexKey(outpoint), &index)
            .await;

        dbtx.insert_new_entry(
            &UnsignedTransactionKey(transaction.compute_txid()),
            &UnsignedTransaction {
                transaction,
                spent_tx_outs: vec![SpentTxOut {
                    value: federation_utxo.value,
                    tweak: None,
                }],
                vbytes: self.cfg.consensus.send_tx_vbytes,
                fee: output.fee,
                created,
            },
        )
        .await;

        let amount = output_value
            .to_sat()
            .checked_mul(1000)
            .map(fedimint_core::Amount::from_msats)
            .ok_or(WalletOutputError::ArithmeticOverflow)?;

        Ok(TransactionItemAmounts {
            amounts: Amounts::new_bitcoin(amount),
            fees: Amounts::new_bitcoin(self.cfg.consensus.fee_consensus.fee(amount)),
        })
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _outpoint: OutPoint,
    ) -> Option<WalletOutputOutcome> {
        None
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        audit
            .add_items(
                dbtx,
                module_instance_id,
                &FederationWalletPrefix,
                |_, federation_utxo| 1000 * federation_utxo.value.to_sat() as i64,
            )
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                CONSENSUS_BLOCK_COUNT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> u64 {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.consensus_block_count(&mut dbtx).await)
                }
            },
            api_endpoint! {
                CONSENSUS_FEERATE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<u64> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.consensus_feerate(&mut dbtx).await)
                }
            },
            api_endpoint! {
                FEDERATION_WALLET_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Wallet, context, _params: ()| -> Option<FederationWallet> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(dbtx.get_value(&FederationWalletKey).await)
                }
            },
            api_endpoint! {
                SEND_FEE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<Amount> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.send_fee(&mut dbtx).await)
                }
            },
            api_endpoint! {
                RECEIVE_FEE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<Amount> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.receive_fee(&mut dbtx).await)
                }
            },
            api_endpoint! {
                TRANSACTION_ID_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, params: OutPoint| -> Option<Txid> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.transaction_id(&mut dbtx, params).await)
                }
            },
            api_endpoint! {
                DEPOSIT_RANGE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, params: (u64, u64)| -> DepositRange {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.get_deposits(&mut dbtx, params.0, params.1).await)
                }
            },
            api_endpoint! {
                PENDING_TRANSACTION_CHAIN_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Vec<TransactionInfo> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.pending_transaction_chain(&mut dbtx).await)
                }
            },
            api_endpoint! {
                TRANSACTION_CHAIN_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, params: usize| -> Vec<TransactionInfo> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.transaction_chain(&mut dbtx, params).await)
                }
            },
        ]
    }
}

#[derive(Debug)]
pub struct Wallet {
    cfg: WalletConfig,
    db: Database,
    btc_rpc: ServerBitcoinRpcMonitor,
}

impl Wallet {
    fn new(
        cfg: WalletConfig,
        db: &Database,
        task_group: &TaskGroup,
        btc_rpc: ServerBitcoinRpcMonitor,
    ) -> Wallet {
        Self::spawn_broadcast_pending_transactions_task(btc_rpc.clone(), db.clone(), task_group);

        Wallet {
            cfg,
            btc_rpc,
            db: db.clone(),
        }
    }

    fn spawn_broadcast_pending_transactions_task(
        btc_rpc: ServerBitcoinRpcMonitor,
        db: Database,
        task_group: &TaskGroup,
    ) {
        task_group.spawn_cancellable("broadcast_pending_transactions", async move {
            loop {
                let pending_transactions = db
                    .begin_transaction_nc()
                    .await
                    .find_by_prefix(&PendingTransactionPrefix)
                    .await
                    .map(|entry| entry.1)
                    .collect::<Vec<PendingTransaction>>()
                    .await;

                for transaction in pending_transactions {
                    btc_rpc.submit_transaction(transaction.transaction).await;
                }

                sleep(common::sleep_duration()).await;
            }
        });
    }

    async fn await_local_sync_to_block_count(&self, block_count: u64) {
        loop {
            if let Some(status) = self.btc_rpc.status() {
                if status.block_count >= block_count {
                    break;
                }
            }

            info!(target: LOG_MODULE_WALLETV2, "Waiting for local bitcoin backend to sync to block count {block_count}");

            sleep(common::sleep_duration()).await;
        }
    }

    pub async fn consensus_block_count(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let num_peers = self.cfg.consensus.bitcoin_pks.to_num_peers();

        let mut counts = dbtx
            .find_by_prefix(&BlockCountVotePrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<u64>>()
            .await;

        assert!(counts.len() <= num_peers.total());

        counts.sort_unstable();

        counts.reverse();

        assert!(counts.last() <= counts.first());

        // The block count we select guarantees that any threshold of correct peers can
        // increase the consensus block count and any consensus block count has been
        // confirmed by a threshold of peers.

        counts.get(num_peers.threshold() - 1).copied().unwrap_or(0)
    }

    pub async fn consensus_feerate(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<u64> {
        let num_peers = self.cfg.consensus.bitcoin_pks.to_num_peers();

        let mut rates = dbtx
            .find_by_prefix(&FeeRateVotePrefix)
            .await
            .filter_map(|entry| async move { entry.1 })
            .collect::<Vec<u64>>()
            .await;

        assert!(rates.len() <= num_peers.total());

        rates.sort_unstable();

        assert!(rates.first() <= rates.last());

        rates.get(num_peers.threshold() - 1).copied()
    }

    pub async fn send_fee(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<Amount> {
        self.consensus_bitcoin_fee(dbtx, self.cfg.consensus.send_tx_vbytes)
            .await
    }

    pub async fn receive_fee(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<Amount> {
        self.consensus_bitcoin_fee(dbtx, self.cfg.consensus.receive_tx_vbytes)
            .await
    }

    pub async fn consensus_bitcoin_fee(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        vbytes: u64,
    ) -> Option<Amount> {
        let unsigned = dbtx
            .find_by_prefix(&UnsignedTransactionPrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<UnsignedTransaction>>()
            .await;

        let pending = dbtx
            .find_by_prefix(&PendingTransactionPrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<PendingTransaction>>()
            .await;

        let mut msats_per_vbyte = self.consensus_feerate(dbtx).await?;

        let transaction_count = unsigned.len() + pending.len();

        // We multiply the feerate by (1/divisor)^n for every unconfirmed transaction

        for _ in 0..transaction_count {
            msats_per_vbyte = msats_per_vbyte
                .saturating_mul(self.cfg.consensus.divisor + 1)
                .saturating_div(self.cfg.consensus.divisor);
        }

        // A stack of 25 unconfirmed transactions will have a minimum average feerate
        // of (50msats << 25) / 1000 = 1.677.700  satoshis per virtual byte. This
        // protects us against a otherwise catastrophic failure of feerate estimation.

        msats_per_vbyte = msats_per_vbyte.max(50 << transaction_count);

        let total_vbytes = vbytes
            + unsigned.iter().map(|u| u.vbytes).sum::<u64>()
            + pending.iter().map(|p| p.vbytes).sum::<u64>();

        let fee = std::cmp::max(
            total_vbytes
                .saturating_mul(msats_per_vbyte)
                .saturating_div(1000)
                .saturating_sub(unsigned.iter().map(|u| u.fee.to_sat()).sum())
                .saturating_sub(pending.iter().map(|u| u.fee.to_sat()).sum()),
            vbytes.saturating_mul(msats_per_vbyte).saturating_div(1000),
        );

        Some(Amount::from_sat(fee))
    }

    fn descriptor(&self, tweak: Option<&sha256::Hash>) -> Wsh<secp256k1::PublicKey> {
        descriptor(&self.cfg.consensus.bitcoin_pks, tweak)
    }

    fn sign_transaction(&self, unsigned_transaction: &UnsignedTransaction) -> Vec<Signature> {
        let mut sighash_cache = SighashCache::new(unsigned_transaction.transaction.clone());

        unsigned_transaction
            .spent_tx_outs
            .iter()
            .enumerate()
            .map(|(index, utxo)| {
                let p2wsh_signature_hash = sighash_cache
                    .p2wsh_signature_hash(
                        index,
                        self.descriptor(utxo.tweak.as_ref())
                            .ecdsa_sighash_script_code()
                            .as_script(),
                        utxo.value,
                        EcdsaSighashType::All,
                    )
                    .expect("Failed to compute P2WSH segwit sighash");

                let sk = match &utxo.tweak {
                    Some(tweak) => {
                        let scalar = &Scalar::from_be_bytes(tweak.to_byte_array())
                            .expect("Hash is within field order");

                        self.cfg
                            .private
                            .bitcoin_sk
                            .add_tweak(scalar)
                            .expect("Failed to tweak bitcoin secret key")
                    }
                    None => self.cfg.private.bitcoin_sk,
                };

                Secp256k1::new().sign_ecdsa(&p2wsh_signature_hash.into(), &sk)
            })
            .collect()
    }

    fn verify_signatures(
        &self,
        unsigned_transaction: &UnsignedTransaction,
        signatures: &[Signature],
        pk: PublicKey,
    ) -> anyhow::Result<()> {
        ensure!(
            unsigned_transaction.spent_tx_outs.len() == signatures.len(),
            "Incorrect number of signatures"
        );

        let mut sighash_cache = SighashCache::new(unsigned_transaction.transaction.clone());

        for ((index, utxo), signature) in unsigned_transaction
            .spent_tx_outs
            .iter()
            .enumerate()
            .zip(signatures.iter())
        {
            let p2wsh_signature_hash = sighash_cache
                .p2wsh_signature_hash(
                    index,
                    self.descriptor(utxo.tweak.as_ref())
                        .ecdsa_sighash_script_code()
                        .as_script(),
                    utxo.value,
                    EcdsaSighashType::All,
                )
                .expect("Failed to compute P2WSH segwit sighash");

            let verification_pk = match &utxo.tweak {
                Some(tweak) => tweak_public_key(&pk, tweak),
                None => pk,
            };

            secp256k1::SECP256K1.verify_ecdsa(
                &p2wsh_signature_hash.into(),
                signature,
                &verification_pk,
            )?;
        }

        Ok(())
    }

    fn finalize_transaction(
        &self,
        unsigned_transaction: &UnsignedTransaction,
        signatures: &BTreeMap<PeerId, Vec<Signature>>,
    ) -> Transaction {
        Psbt {
            unsigned_tx: unsigned_transaction.transaction.clone(),
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: unsigned_transaction
                .spent_tx_outs
                .iter()
                .enumerate()
                .map(|(index, utxo)| Input {
                    witness_utxo: Some(TxOut {
                        value: utxo.value,
                        script_pubkey: self.descriptor(utxo.tweak.as_ref()).script_pubkey(),
                    }),
                    witness_script: Some(
                        self.descriptor(utxo.tweak.as_ref())
                            .ecdsa_sighash_script_code(),
                    ),
                    partial_sigs: signatures
                        .iter()
                        .map(|(peer, signatures)| {
                            let pk = *self
                                .cfg
                                .consensus
                                .bitcoin_pks
                                .get(peer)
                                .expect("Failed to get public key of peer {peer} from config");

                            let pk = match &utxo.tweak {
                                Some(tweak) => {
                                    bitcoin::PublicKey::new(tweak_public_key(&pk, tweak))
                                }
                                None => bitcoin::PublicKey::new(pk),
                            };

                            let sig = bitcoin::ecdsa::Signature::sighash_all(signatures[index]);

                            (pk, sig)
                        })
                        .collect(),
                    ..Default::default()
                })
                .collect(),
            outputs: vec![Default::default()],
        }
        .finalize(secp256k1::SECP256K1)
        .expect("Failed to finalize PSBT")
        .extract_tx_unchecked_fee_rate()
    }

    async fn transaction_id(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        outpoint: OutPoint,
    ) -> Option<Txid> {
        let index = dbtx.get_value(&TransactionLogIndexKey(outpoint)).await?;

        self.transaction_info(dbtx, index)
            .await
            .map(|info| info.txid)
    }

    async fn get_deposits(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        start_index: u64,
        end_index: u64,
    ) -> DepositRange {
        let deposits = dbtx
            .find_by_range(DepositKey(start_index)..DepositKey(end_index))
            .await
            .map(|entry| entry.1.1)
            .collect()
            .await;

        let spent = dbtx
            .find_by_range(SpentDepositKey(start_index)..SpentDepositKey(end_index))
            .await
            .map(|entry| entry.0.0)
            .collect()
            .await;

        DepositRange { deposits, spent }
    }

    async fn pending_transaction_chain(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<TransactionInfo> {
        let n_unsigned = dbtx
            .find_by_prefix(&UnsignedTransactionPrefix)
            .await
            .count()
            .await;

        let n_pending = dbtx
            .find_by_prefix(&PendingTransactionPrefix)
            .await
            .count()
            .await;

        dbtx.find_by_prefix_sorted_descending(&TransactionLogPrefix)
            .await
            .skip(n_unsigned)
            .take(n_pending)
            .map(|(key, entry)| TransactionInfo {
                index: key.0,
                txid: entry.transaction.compute_txid(),
                input: entry.input,
                output: entry.output,
                vbytes: entry.vbytes,
                fee: entry.fee,
                feerate: entry.fee.to_sat() / entry.vbytes,
                created: entry.created,
            })
            .collect()
            .await
    }

    async fn transaction_chain(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        n: usize,
    ) -> Vec<TransactionInfo> {
        dbtx.find_by_prefix_sorted_descending(&TransactionLogPrefix)
            .await
            .take(n)
            .map(|(key, entry)| TransactionInfo {
                index: key.0,
                txid: entry.transaction.compute_txid(),
                input: entry.input,
                output: entry.output,
                vbytes: entry.vbytes,
                fee: entry.fee,
                feerate: entry.fee.to_sat() / entry.vbytes,
                created: entry.created,
            })
            .collect()
            .await
    }

    async fn transaction_info(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        index: u64,
    ) -> Option<TransactionInfo> {
        dbtx.get_value(&TransactionLogKey(index))
            .await
            .map(|entry| TransactionInfo {
                index,
                txid: entry.transaction.compute_txid(),
                input: entry.input,
                output: entry.output,
                vbytes: entry.vbytes,
                fee: entry.fee,
                feerate: entry.fee.to_sat() / entry.vbytes,
                created: entry.created,
            })
    }

    async fn total_transactions(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        dbtx.find_by_prefix(&TransactionLogPrefix)
            .await
            .count()
            .await as u64
    }

    /// Get the network for UI display
    pub fn network_ui(&self) -> Network {
        self.cfg.consensus.network
    }

    /// Get the current federation wallet info for UI display
    pub async fn federation_wallet_ui(&self) -> Option<FederationWallet> {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&FederationWalletKey)
            .await
    }

    /// Get the current consensus block count for UI display
    pub async fn consensus_block_count_ui(&self) -> u64 {
        self.consensus_block_count(&mut self.db.begin_transaction_nc().await)
            .await
    }

    /// Get the current consensus feerate for UI display
    pub async fn consensus_feerate_ui(&self) -> Option<u64> {
        self.consensus_feerate(&mut self.db.begin_transaction_nc().await)
            .await
            .map(|feerate| feerate / 1000)
    }

    /// Get the current send fee for UI display
    pub async fn send_fee_ui(&self) -> Option<Amount> {
        self.send_fee(&mut self.db.begin_transaction_nc().await)
            .await
    }

    /// Get the current receive fee for UI display
    pub async fn receive_fee_ui(&self) -> Option<Amount> {
        self.receive_fee(&mut self.db.begin_transaction_nc().await)
            .await
    }

    /// Get the current pending transaction info for UI display
    pub async fn pending_transaction_chain_ui(&self) -> Vec<TransactionInfo> {
        self.pending_transaction_chain(&mut self.db.begin_transaction_nc().await)
            .await
    }

    /// Get the current transaction log for UI display
    pub async fn transaction_chain_ui(&self, n: usize) -> Vec<TransactionInfo> {
        self.transaction_chain(&mut self.db.begin_transaction_nc().await, n)
            .await
    }

    /// Get the federation address for UI display
    pub fn federation_address_ui(&self) -> String {
        bitcoin::Address::from_script(
            &self.descriptor(None).script_pubkey(),
            self.cfg.consensus.network,
        )
        .expect("Failed to create address from script")
        .to_string()
    }

    /// Export the watch-only descriptor for federation shutdown
    pub fn export_descriptor_ui(&self) -> String {
        format!("{}", descriptor(&self.cfg.consensus.bitcoin_pks, None))
    }

    /// Export this guardian's private key in WIF format for federation shutdown
    pub fn export_private_key_wif_ui(&self) -> String {
        bitcoin::PrivateKey {
            compressed: true,
            network: self.cfg.consensus.network.into(),
            inner: self.cfg.private.bitcoin_sk,
        }
        .to_wif()
    }
}

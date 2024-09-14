#![deny(clippy::pedantic)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]

pub mod db;

use std::collections::{BTreeMap, BTreeSet};
#[cfg(not(target_family = "wasm"))]
use std::time::Duration;

use anyhow::{bail, ensure, Context};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Input;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, Psbt, Sequence, Transaction, TxIn, TxOut, Txid};
use common::config::WalletConfigConsensus;
use common::{
    WalletCommonInit, WalletConsensusItem, WalletInput, WalletModuleTypes, WalletOutput,
    WalletOutputOutcome,
};
use db::{
    FederationWalletKey, FederationWalletPrefix, FeeRateIndexKey, SignaturesKey,
    SignaturesTxidPrefix, SpentOutPointPrefix, TransactionLogIndexKey,
};
use fedimint_bitcoind::{create_bitcoind, DynBitcoindRpc};
use fedimint_core::config::{
    ConfigGenModuleParams, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiVersion, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, SupportedModuleApiVersions, TransactionItemAmount, CORE_CONSENSUS_VERSION,
};
use fedimint_core::task::sleep;
#[cfg(not(target_family = "wasm"))]
use fedimint_core::task::TaskGroup;
use fedimint_core::{apply, async_trait_maybe_send, util, InPoint, NumPeersExt, OutPoint, PeerId};
use fedimint_server_core::config::{PeerHandleOps, PeerHandleOpsExt};
use fedimint_server_core::{ServerModule, ServerModuleInit, ServerModuleInitArgs};
pub use fedimint_walletv2_common as common;
use fedimint_walletv2_common::config::{
    WalletClientConfig, WalletConfig, WalletConfigLocal, WalletConfigPrivate, WalletGenParams,
};
use fedimint_walletv2_common::endpoint_constants::{
    CONSENSUS_BLOCK_COUNT_ENDPOINT, CONSENSUS_FEERATE_ENDPOINT, FEDERATION_WALLET_ENDPOINT,
    FILTER_UNSPENT_OUTPOINTS_ENDPOINT, PENDING_TRANSACTION_CHAIN_ENDPOINT, RECEIVE_FEE_ENDPOINT,
    SEND_FEE_ENDPOINT, TRANSACTION_CHAIN_ENDPOINT, TRANSACTION_ID_ENDPOINT,
    TRANSACTION_INFO_ENDPOINT,
};
use fedimint_walletv2_common::{
    descriptor, tweak_public_key, FederationWallet, ReceiveFee, SendFee, TransactionInfo,
    WalletInputError, WalletOutputError, MODULE_CONSENSUS_VERSION,
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
    PendingTransactionKey, PendingTransactionPrefix, SpentOutPointKey, TransactionLogKey,
    TransactionLogPrefix, UnsignedTransactionKey, UnsignedTransactionPrefix, UnspentTxOutKey,
};

/// Used for estimating a feerate that will confirm within a target number of
/// blocks.
///
/// Since the wallet's UTXOs are a shared resource, we need to reduce the risk
/// of a peg-out transaction getting stuck in the mempool, hence we use a low
/// confirmation target. Other fee bumping techniques, such as RBF and CPFP, can
/// help mitigate this problem but are out-of-scope for this version of the
/// wallet.
pub const CONFIRMATION_TARGET: u16 = 1;

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
    pub tweak: sha256::Hash,
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
    type Params = WalletGenParams;

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
        Wallet::new(args.cfg().to_typed()?, args.db(), args.task_group())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let params = self
            .parse_params(params)
            .expect("Failed to parse wallet config gen parameters");

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
                    local: WalletConfigLocal {
                        bitcoin_rpc: params.local.bitcoin_rpc.clone(),
                    },
                    private: WalletConfigPrivate { bitcoin_sk },
                    consensus: WalletConfigConsensus::new(
                        bitcoin_pks.clone(),
                        params.consensus.fee_consensus.clone(),
                        params.consensus.network,
                    ),
                };

                (peer, config.to_erased())
            })
            .collect()
    }

    async fn distributed_gen(
        &self,
        peers: &(dyn PeerHandleOps + Send + Sync),
        params: &ConfigGenModuleParams,
    ) -> anyhow::Result<ServerModuleConfig> {
        let params = self
            .parse_params(params)
            .expect("Failed to parse wallet config gen parameters");

        let (bitcoin_sk, bitcoin_pk) = secp256k1::generate_keypair(&mut OsRng);

        let bitcoin_pks: BTreeMap<PeerId, PublicKey> = peers
            .exchange_encodable(bitcoin_pk)
            .await?
            .into_iter()
            .collect();

        let config = WalletConfig {
            local: WalletConfigLocal {
                bitcoin_rpc: params.local.bitcoin_rpc.clone(),
            },
            private: WalletConfigPrivate { bitcoin_sk },
            consensus: WalletConfigConsensus::new(
                bitcoin_pks,
                params.consensus.fee_consensus,
                params.consensus.network,
            ),
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
            finality_delay: config.finality_delay,
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

        let network = util::retry(
            "get_network",
            util::backoff_util::background_backoff(),
            || self.btc_rpc.get_network(),
        )
        .await
        .expect("Bitcoind rpc to get_network failed");

        assert_eq!(network, self.cfg.consensus.network);

        if let Ok(block_count) = self.btc_rpc.get_block_count().await {
            items.push(WalletConsensusItem::BlockCount(
                block_count.saturating_sub(self.cfg.consensus.finality_delay),
            ));
        }

        // If we cannot fetch a up to date feerate from our bitcoin backend we need to
        // retract our last vote on the feerate as an outdated consensus feerate can get
        // our transactions stuck.
        if let Ok(Some(fee_rate)) = self.btc_rpc.get_fee_rate(CONFIRMATION_TARGET).await {
            items.push(WalletConsensusItem::Feerate(Some(fee_rate.sats_per_kvb)));
        } else {
            // Regtest node never returns fee rate
            if self.cfg.consensus.network == Network::Regtest {
                items.push(WalletConsensusItem::Feerate(Some(1000)));
            } else {
                items.push(WalletConsensusItem::Feerate(None));
            }
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
                self.await_local_sync_to_block_count(
                    new_consensus_block_count + self.cfg.consensus.finality_delay,
                )
                .await;

                for height in old_consensus_block_count..new_consensus_block_count {
                    let network = util::retry(
                        "get_network",
                        util::backoff_util::background_backoff(),
                        || self.btc_rpc.get_network(),
                    )
                    .await
                    .expect("Bitcoind rpc to get_network failed");

                    assert_eq!(network, self.cfg.consensus.network);

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

                    for transaction in block.txdata {
                        if dbtx
                            .remove_entry(&PendingTransactionKey(transaction.compute_txid()))
                            .await
                            .is_some()
                        {
                            self.increment_feerate_index(dbtx).await;
                        }

                        // We maintain the set of unspent P2WSH transaction outputs created
                        // since the federation was established.

                        for tx_in in &transaction.input {
                            dbtx.remove_entry(&UnspentTxOutKey(tx_in.previous_output))
                                .await;
                        }

                        for (vout, tx_out) in transaction.output.iter().enumerate() {
                            if tx_out.script_pubkey.is_p2wsh() {
                                let outpoint = bitcoin::OutPoint {
                                    txid: transaction.compute_txid(),
                                    vout: u32::try_from(vout).expect(
                                        "Bitcoin transaction has more then u32::MAX outputs",
                                    ),
                                };

                                dbtx.insert_new_entry(&UnspentTxOutKey(outpoint), tx_out)
                                    .await;
                            }
                        }
                    }
                }
            }
            WalletConsensusItem::Feerate(feerate) => {
                let old_median = self.consensus_feerate(dbtx).await;

                if Some(feerate) == dbtx.insert_entry(&FeeRateVoteKey(peer), &feerate).await {
                    bail!("Fee rate vote is redundant");
                }

                if old_median != self.consensus_feerate(dbtx).await {
                    self.increment_feerate_index(dbtx).await;
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
            .insert_entry(&SpentOutPointKey(input.outpoint), &())
            .await
            .is_some()
        {
            return Err(WalletInputError::UnspentTxOutAlreadySpent);
        }

        let input_tx_out = dbtx
            .get_value(&UnspentTxOutKey(input.outpoint))
            .await
            .ok_or(WalletInputError::UnknownUnspentTxOut)?;

        if input_tx_out.script_pubkey
            != self
                .descriptor(&input.tweak.consensus_hash())
                .script_pubkey()
        {
            return Err(WalletInputError::WrongOutputScript);
        }

        let consensus_receive_fee = self
            .receive_fee(dbtx)
            .await
            .ok_or(WalletInputError::NoConsensusFeerateAvailable)?;

        if input.fee.index != consensus_receive_fee.index {
            return Err(WalletInputError::IncorrectFeeRateIndex);
        }

        // We allow for a higher fee such that a guardian could construct a CPFP
        // transaction. This is the last line of defense should the federations
        // transactions ever get stuck due to a critical failure of the feerate
        // estimation.
        if input.fee.value < consensus_receive_fee.value {
            return Err(WalletInputError::InsufficientTotalFee);
        }

        let pegin_value = input_tx_out
            .value
            .checked_sub(input.fee.value)
            .ok_or(WalletInputError::ArithmeticOverflow)?;

        match dbtx.remove_entry(&FederationWalletKey).await {
            Some(federation_utxo) => {
                // The change is non-zero as it contains the fees taken by the federation
                let change_value = federation_utxo
                    .value
                    .checked_add(pegin_value)
                    .ok_or(WalletInputError::ArithmeticOverflow)?;

                let transaction = Transaction {
                    version: Version(2),
                    lock_time: LockTime::ZERO,
                    input: vec![
                        TxIn {
                            previous_output: federation_utxo.outpoint,
                            script_sig: Default::default(),
                            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                            witness: bitcoin::Witness::new(),
                        },
                        TxIn {
                            previous_output: input.outpoint,
                            script_sig: Default::default(),
                            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                            witness: bitcoin::Witness::new(),
                        },
                    ],
                    output: vec![TxOut {
                        value: change_value,
                        script_pubkey: self
                            .descriptor(&federation_utxo.consensus_hash())
                            .script_pubkey(),
                    }],
                };

                dbtx.insert_new_entry(
                    &FederationWalletKey,
                    &FederationWallet {
                        value: change_value,
                        outpoint: bitcoin::OutPoint {
                            txid: transaction.compute_txid(),
                            vout: 0,
                        },
                        tweak: federation_utxo.consensus_hash(),
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
                        vbytes: self.cfg.consensus.receive_tx_vbytes,
                        fee: input.fee.value,
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
                                value: federation_utxo.value,
                                tweak: federation_utxo.tweak,
                            },
                            SpentTxOut {
                                value: input_tx_out.value,
                                tweak: input.tweak.consensus_hash(),
                            },
                        ],
                        vbytes: self.cfg.consensus.receive_tx_vbytes,
                        fee: input.fee.value,
                        created,
                    },
                )
                .await;

                self.increment_feerate_index(dbtx).await;
            }
            None => {
                dbtx.insert_new_entry(
                    &FederationWalletKey,
                    &FederationWallet {
                        value: input_tx_out.value,
                        outpoint: input.outpoint,
                        tweak: input.tweak.consensus_hash(),
                    },
                )
                .await;
            }
        };

        let amount = pegin_value
            .to_sat()
            .checked_mul(1000)
            .map(fedimint_core::Amount::from_msats)
            .ok_or(WalletInputError::ArithmeticOverflow)?;

        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount,
                fee: self.cfg.consensus.fee_consensus.fee(amount),
            },
            pub_key: input.tweak,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a WalletOutput,
        outpoint: OutPoint,
    ) -> Result<TransactionItemAmount, WalletOutputError> {
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

        if output.fee.index != consensus_send_fee.index {
            return Err(WalletOutputError::IncorrectFeeRateIndex);
        }

        // We allow for a higher fee such that a guardian could construct a CPFP
        // transaction. This is the last line of defense should the federations
        // transactions ever get stuck due to a critical failure of the feerate
        // estimation.
        if output.fee.value < consensus_send_fee.value {
            return Err(WalletOutputError::InsufficicentTotalFee);
        }

        let output_value = output
            .value
            .checked_add(output.fee.value)
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
                previous_output: federation_utxo.outpoint,
                script_sig: Default::default(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: change_value,
                    script_pubkey: self
                        .descriptor(&federation_utxo.consensus_hash())
                        .script_pubkey(),
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
                outpoint: bitcoin::OutPoint {
                    txid: transaction.compute_txid(),
                    vout: 0,
                },
                value: change_value,
                tweak: federation_utxo.consensus_hash(),
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
                fee: output.fee.value,
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
                    tweak: federation_utxo.tweak,
                }],
                vbytes: self.cfg.consensus.send_tx_vbytes,
                fee: output.fee.value,
                created,
            },
        )
        .await;

        self.increment_feerate_index(dbtx).await;

        let amount = output_value
            .to_sat()
            .checked_mul(1000)
            .map(fedimint_core::Amount::from_msats)
            .ok_or(WalletOutputError::ArithmeticOverflow)?;

        Ok(TransactionItemAmount {
            amount,
            fee: self.cfg.consensus.fee_consensus.fee(amount),
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
                    Ok(module.consensus_block_count(&mut context.dbtx().into_nc()).await)
                }
            },
            api_endpoint! {
                CONSENSUS_FEERATE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<u64> {
                    Ok(module.consensus_feerate(&mut context.dbtx().into_nc()).await)
                }
            },
            api_endpoint! {
                FEDERATION_WALLET_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Wallet, context, _params: ()| -> Option<FederationWallet> {
                    Ok(context.dbtx().into_nc().get_value(&FederationWalletKey).await)

                }
            },
            api_endpoint! {
                SEND_FEE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<SendFee> {
                    Ok(module.send_fee(&mut context.dbtx().into_nc()).await)
                }
            },
            api_endpoint! {
                RECEIVE_FEE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<ReceiveFee> {
                    Ok(module.receive_fee(&mut context.dbtx().into_nc()).await)
                }
            },
            api_endpoint! {
                TRANSACTION_ID_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, params: OutPoint| -> Option<Txid> {
                    Ok(module.transaction_id(&mut context.dbtx().into_nc(), params).await)
                }
            },
            api_endpoint! {
                FILTER_UNSPENT_OUTPOINTS_ENDPOINT,
                ApiVersion::new(0, 1),
                async |module: &Wallet, context, params: BTreeSet<bitcoin::OutPoint>| -> BTreeSet<bitcoin::OutPoint> {
                    Ok(module.filter_unspent_outpoints(&mut context.dbtx().into_nc(),params).await)
                }
            },
            api_endpoint! {
                PENDING_TRANSACTION_CHAIN_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Vec<TransactionInfo> {
                    Ok(module.pending_transaction_chain(&mut context.dbtx().into_nc()).await)
                }
            },
            api_endpoint! {
                TRANSACTION_CHAIN_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, params: usize| -> Vec<TransactionInfo> {
                    Ok(module.transaction_chain(&mut context.dbtx().into_nc(), params).await)
                }
            },
            api_endpoint! {
                TRANSACTION_INFO_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, params: u64| -> Option<TransactionInfo> {
                    Ok(module.transaction_info(&mut context.dbtx().into_nc(), params).await)
                }
            },
        ]
    }
}

#[derive(Debug)]
pub struct Wallet {
    cfg: WalletConfig,
    db: Database,
    btc_rpc: DynBitcoindRpc,
}

impl Wallet {
    fn new(cfg: WalletConfig, db: &Database, task_group: &TaskGroup) -> anyhow::Result<Wallet> {
        let btc_rpc = create_bitcoind(&cfg.local.bitcoin_rpc)?;

        Self::spawn_broadcast_pending_transactions_task(btc_rpc.clone(), db.clone(), task_group);

        Ok(Wallet {
            cfg,
            btc_rpc,
            db: db.clone(),
        })
    }

    fn spawn_broadcast_pending_transactions_task(
        bitcoind: DynBitcoindRpc,
        db: Database,
        task_group: &TaskGroup,
    ) {
        task_group.spawn_cancellable("broadcast_pending_transactions", async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

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
                    bitcoind.submit_transaction(transaction.transaction).await;
                }

                interval.tick().await;
            }
        });
    }

    async fn await_local_sync_to_block_count(&self, block_count: u64) {
        loop {
            if let Ok(local_block_count) = self.btc_rpc.get_block_count().await {
                if local_block_count >= block_count {
                    break;
                }
            }

            info!("Waiting for local bitcoin backend to sync to block count {block_count}");

            sleep(Duration::from_secs(10)).await;
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

    // The index needs to be incremented every time the consensus feerate changes
    async fn increment_feerate_index(&self, dbtx: &mut DatabaseTransaction<'_>) {
        let index = dbtx
            .remove_entry(&FeeRateIndexKey)
            .await
            .unwrap_or(0)
            .checked_add(1)
            .expect("Failed to increment feerate index");

        dbtx.insert_new_entry(&FeeRateIndexKey, &index).await;
    }

    pub async fn send_fee(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<SendFee> {
        let index = dbtx.get_value(&FeeRateIndexKey).await.unwrap_or(0);

        self.consensus_bitcoin_fee(dbtx, self.cfg.consensus.send_tx_vbytes)
            .await
            .map(|value| SendFee { index, value })
    }

    pub async fn receive_fee(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<ReceiveFee> {
        let index = dbtx.get_value(&FeeRateIndexKey).await.unwrap_or(0);

        self.consensus_bitcoin_fee(dbtx, self.cfg.consensus.receive_tx_vbytes)
            .await
            .map(|value| ReceiveFee { index, value })
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

    fn descriptor(&self, tweak: &sha256::Hash) -> Wsh<secp256k1::PublicKey> {
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
                        self.descriptor(&utxo.tweak)
                            .ecdsa_sighash_script_code()
                            .as_script(),
                        utxo.value,
                        EcdsaSighashType::All,
                    )
                    .expect("Failed to compute P2WSH segwit sighash");

                let sk = self
                    .cfg
                    .private
                    .bitcoin_sk
                    .add_tweak(
                        &Scalar::from_be_bytes(utxo.tweak.to_byte_array())
                            .expect("Hash is within field order"),
                    )
                    .expect("Failed to tweak bitcoin secret key");

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
                    self.descriptor(&utxo.tweak)
                        .ecdsa_sighash_script_code()
                        .as_script(),
                    utxo.value,
                    EcdsaSighashType::All,
                )
                .expect("Failed to compute P2WSH segwit sighash");

            secp256k1::SECP256K1.verify_ecdsa(
                &p2wsh_signature_hash.into(),
                signature,
                &tweak_public_key(&pk, &utxo.tweak),
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
                        script_pubkey: self.descriptor(&utxo.tweak).script_pubkey(),
                    }),
                    witness_script: Some(self.descriptor(&utxo.tweak).ecdsa_sighash_script_code()),
                    partial_sigs: signatures
                        .iter()
                        .map(|(peer, signatures)| {
                            let pk = *self
                                .cfg
                                .consensus
                                .bitcoin_pks
                                .get(peer)
                                .expect("Failed to get public key of peer {peer} from config");

                            let pk = bitcoin::PublicKey::new(tweak_public_key(&pk, &utxo.tweak));

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

    async fn filter_unspent_outpoints(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        outpoints: BTreeSet<bitcoin::OutPoint>,
    ) -> BTreeSet<bitcoin::OutPoint> {
        let claimed_outpoints = dbtx
            .find_by_prefix(&SpentOutPointPrefix)
            .await
            .map(|entry| entry.0 .0)
            .collect::<BTreeSet<bitcoin::OutPoint>>()
            .await;

        outpoints.difference(&claimed_outpoints).copied().collect()
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
        n_transactions: usize,
    ) -> Vec<TransactionInfo> {
        dbtx.find_by_prefix_sorted_descending(&TransactionLogPrefix)
            .await
            .take(n_transactions)
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
    pub async fn send_fee_ui(&self) -> Option<SendFee> {
        self.send_fee(&mut self.db.begin_transaction_nc().await)
            .await
    }

    /// Get the current receive fee for UI display
    pub async fn receive_fee_ui(&self) -> Option<ReceiveFee> {
        self.receive_fee(&mut self.db.begin_transaction_nc().await)
            .await
    }

    /// Get the current pending transaction info for UI display
    pub async fn pending_transaction_chain_ui(&self) -> Vec<TransactionInfo> {
        self.pending_transaction_chain(&mut self.db.begin_transaction_nc().await)
            .await
    }

    /// Get the current transaction log for UI display
    pub async fn transaction_chain_ui(&self) -> Vec<TransactionInfo> {
        self.transaction_chain(&mut self.db.begin_transaction_nc().await, 100)
            .await
    }
}

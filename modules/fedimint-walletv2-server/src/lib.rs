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

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, anyhow, bail, ensure};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, Sequence, Transaction, TxIn, TxOut, Txid};
use common::config::WalletConfigConsensus;
use common::{
    DepositRange, WalletCommonInit, WalletConsensusItem, WalletInput, WalletModuleTypes,
    WalletOutput, WalletOutputOutcome,
};
use db::{
    DbKeyPrefix, Deposit, DepositKey, DepositPrefix, FederationWalletKey, FederationWalletPrefix,
    SignaturesKey, SignaturesPrefix, SignaturesTxidPrefix, SpentDepositKey, SpentDepositPrefix,
    TxInfoIndexKey, TxInfoIndexPrefix,
};
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::{FM_ENABLE_MODULE_WALLETV2_ENV, is_env_var_set_opt};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiVersion, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta,
    ModuleConsensusVersion, ModuleInit, SupportedModuleApiVersions, TransactionItemAmounts,
    api_endpoint,
};
#[cfg(not(target_family = "wasm"))]
use fedimint_core::task::TaskGroup;
use fedimint_core::task::sleep;
use fedimint_core::{
    InPoint, NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send, push_db_pair_items, util,
};
use fedimint_logging::LOG_MODULE_WALLETV2;
use fedimint_server_core::bitcoin_rpc::ServerBitcoinRpcMonitor;
use fedimint_server_core::config::{PeerHandleOps, PeerHandleOpsExt};
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
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
    FederationWallet, MODULE_CONSENSUS_VERSION, TxInfo, WalletInputError, WalletOutputError,
    descriptor, is_potential_receive, tweak_public_key,
};
use futures::StreamExt;
use miniscript::descriptor::Wsh;
use rand::rngs::OsRng;
use secp256k1::ecdsa::Signature;
use secp256k1::{PublicKey, Scalar, SecretKey};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tracing::info;

use crate::db::{
    BlockCountVoteKey, BlockCountVotePrefix, FeeRateVoteKey, FeeRateVotePrefix, TxInfoKey,
    TxInfoPrefix, UnconfirmedTxKey, UnconfirmedTxPrefix, UnsignedTxKey, UnsignedTxPrefix,
};

/// Number of confirmations required for a transaction to be considered as
/// final by the federation. The block that mines the transaction does
/// not count towards the number of confirmations.
pub const CONFIRMATION_FINALITY_DELAY: u64 = 6;

/// Maximum number of blocks the consensus block count can advance in a single
/// consensus item to limit the work done in one `process_consensus_item` step.
const MAX_BLOCK_COUNT_INCREMENT: u64 = 5;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Encodable, Decodable)]
pub struct FederationTx {
    pub tx: Transaction,
    pub spent_tx_outs: Vec<SpentTxOut>,
    pub vbytes: u64,
    pub fee: Amount,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct SpentTxOut {
    pub value: Amount,
    pub tweak: sha256::Hash,
}

async fn pending_txs_unordered(dbtx: &mut DatabaseTransaction<'_>) -> Vec<FederationTx> {
    let unsigned: Vec<FederationTx> = dbtx
        .find_by_prefix(&UnsignedTxPrefix)
        .await
        .map(|entry| entry.1)
        .collect()
        .await;

    let unconfirmed: Vec<FederationTx> = dbtx
        .find_by_prefix(&UnconfirmedTxPrefix)
        .await
        .map(|entry| entry.1)
        .collect()
        .await;

    unsigned.into_iter().chain(unconfirmed).collect()
}

#[derive(Debug, Clone)]
pub struct WalletInit;

impl ModuleInit for WalletInit {
    type Common = WalletCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut wallet: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();

        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::Deposit => {
                    push_db_pair_items!(
                        dbtx,
                        DepositPrefix,
                        DepositKey,
                        Deposit,
                        wallet,
                        "Wallet Deposits"
                    );
                }
                DbKeyPrefix::SpentDeposit => {
                    push_db_pair_items!(
                        dbtx,
                        SpentDepositPrefix,
                        SpentDepositKey,
                        (),
                        wallet,
                        "Wallet Spent Deposits"
                    );
                }
                DbKeyPrefix::BlockCountVote => {
                    push_db_pair_items!(
                        dbtx,
                        BlockCountVotePrefix,
                        BlockCountVoteKey,
                        u64,
                        wallet,
                        "Wallet Block Count Votes"
                    );
                }
                DbKeyPrefix::FeeRateVote => {
                    push_db_pair_items!(
                        dbtx,
                        FeeRateVotePrefix,
                        FeeRateVoteKey,
                        Option<u64>,
                        wallet,
                        "Wallet Fee Rate Votes"
                    );
                }
                DbKeyPrefix::TxLog => {
                    push_db_pair_items!(
                        dbtx,
                        TxInfoPrefix,
                        TxInfoKey,
                        TxInfo,
                        wallet,
                        "Wallet Tx Log"
                    );
                }
                DbKeyPrefix::TxInfoIndex => {
                    push_db_pair_items!(
                        dbtx,
                        TxInfoIndexPrefix,
                        TxInfoIndexKey,
                        u64,
                        wallet,
                        "Wallet Tx Info Index"
                    );
                }
                DbKeyPrefix::UnsignedTx => {
                    push_db_pair_items!(
                        dbtx,
                        UnsignedTxPrefix,
                        UnsignedTxKey,
                        FederationTx,
                        wallet,
                        "Wallet Unsigned Transactions"
                    );
                }
                DbKeyPrefix::Signatures => {
                    push_db_pair_items!(
                        dbtx,
                        SignaturesPrefix,
                        SignaturesKey,
                        Vec<Signature>,
                        wallet,
                        "Wallet Signatures"
                    );
                }
                DbKeyPrefix::UnconfirmedTx => {
                    push_db_pair_items!(
                        dbtx,
                        UnconfirmedTxPrefix,
                        UnconfirmedTxKey,
                        FederationTx,
                        wallet,
                        "Wallet Unconfirmed Transactions"
                    );
                }
                DbKeyPrefix::FederationWallet => {
                    push_db_pair_items!(
                        dbtx,
                        FederationWalletPrefix,
                        FederationWalletKey,
                        FederationWallet,
                        wallet,
                        "Federation Wallet"
                    );
                }
            }
        }

        Box::new(wallet.into_iter())
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

    fn is_enabled_by_default(&self) -> bool {
        is_env_var_set_opt(FM_ENABLE_MODULE_WALLETV2_ENV).unwrap_or(false)
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

    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Wallet>> {
        BTreeMap::new()
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        Some(DbKeyPrefix::iter().map(|p| p as u8).collect())
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
            .find_by_prefix(&UnsignedTxPrefix)
            .await
            .map(|(key, unsigned_tx)| {
                let signatures = self.sign_tx(&unsigned_tx);

                assert!(
                    self.verify_signatures(
                        &unsigned_tx,
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

            items.push(WalletConsensusItem::BlockCount(
                status
                    .block_count
                    .saturating_sub(CONFIRMATION_FINALITY_DELAY)
                    .min(consensus_block_count + MAX_BLOCK_COUNT_INCREMENT),
            ));

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
                self.process_block_count(dbtx, block_count_vote, peer).await
            }
            WalletConsensusItem::Feerate(feerate) => {
                if Some(feerate) == dbtx.insert_entry(&FeeRateVoteKey(peer), &feerate).await {
                    return Err(anyhow!("Fee rate vote is redundant"));
                }

                Ok(())
            }
            WalletConsensusItem::Signatures(txid, signatures) => {
                self.process_signatures(dbtx, txid, signatures, peer).await
            }
            WalletConsensusItem::Default { variant, .. } => Err(anyhow!(
                "Received wallet consensus item with unknown variant {variant}"
            )),
        }
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

        let Deposit(tracked_outpoint, tracked_out) = dbtx
            .get_value(&DepositKey(input.deposit_index))
            .await
            .ok_or(WalletInputError::UnknownDepositIndex)?;

        let tweaked_pubkey = self
            .descriptor(&input.tweak.consensus_hash())
            .script_pubkey();

        if tracked_out.script_pubkey != tweaked_pubkey {
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

        let deposit_value = tracked_out
            .value
            .checked_sub(input.fee)
            .ok_or(WalletInputError::ArithmeticOverflow)?;

        if let Some(wallet) = dbtx.remove_entry(&FederationWalletKey).await {
            // Assuming the first receive into the federation is made through a
            // standard transaction, its output value is over the P2WSH dust
            // limit. By induction so is this change value.
            let change_value = wallet
                .value
                .checked_add(deposit_value)
                .ok_or(WalletInputError::ArithmeticOverflow)?;

            let tx = Transaction {
                version: Version(2),
                lock_time: LockTime::ZERO,
                input: vec![
                    TxIn {
                        previous_output: wallet.outpoint,
                        script_sig: Default::default(),
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: bitcoin::Witness::new(),
                    },
                    TxIn {
                        previous_output: tracked_outpoint,
                        script_sig: Default::default(),
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: bitcoin::Witness::new(),
                    },
                ],
                output: vec![TxOut {
                    value: change_value,
                    script_pubkey: self.descriptor(&wallet.consensus_hash()).script_pubkey(),
                }],
            };

            dbtx.insert_new_entry(
                &FederationWalletKey,
                &FederationWallet {
                    value: change_value,
                    outpoint: bitcoin::OutPoint {
                        txid: tx.compute_txid(),
                        vout: 0,
                    },
                    tweak: wallet.consensus_hash(),
                },
            )
            .await;

            let tx_index = self.total_txs(dbtx).await;

            let created = self.consensus_block_count(dbtx).await;

            dbtx.insert_new_entry(
                &TxInfoKey(tx_index),
                &TxInfo {
                    index: tx_index,
                    txid: tx.compute_txid(),
                    input: wallet.value,
                    output: change_value,
                    vbytes: self.cfg.consensus.receive_tx_vbytes,
                    fee: input.fee,
                    created,
                },
            )
            .await;

            dbtx.insert_new_entry(
                &UnsignedTxKey(tx.compute_txid()),
                &FederationTx {
                    tx,
                    spent_tx_outs: vec![
                        SpentTxOut {
                            value: wallet.value,
                            tweak: wallet.tweak,
                        },
                        SpentTxOut {
                            value: tracked_out.value,
                            tweak: input.tweak.consensus_hash(),
                        },
                    ],
                    vbytes: self.cfg.consensus.receive_tx_vbytes,
                    fee: input.fee,
                },
            )
            .await;
        } else {
            dbtx.insert_new_entry(
                &FederationWalletKey,
                &FederationWallet {
                    value: tracked_out.value,
                    outpoint: tracked_outpoint,
                    tweak: input.tweak.consensus_hash(),
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

        let wallet = dbtx
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
            return Err(WalletOutputError::InsufficientTotalFee);
        }

        let output_value = output
            .value
            .checked_add(output.fee)
            .ok_or(WalletOutputError::ArithmeticOverflow)?;

        let change_value = wallet
            .value
            .checked_sub(output_value)
            .ok_or(WalletOutputError::ArithmeticOverflow)?;

        if change_value < self.cfg.consensus.dust_limit {
            return Err(WalletOutputError::ChangeUnderDustLimit);
        }

        let script_pubkey = output
            .destination
            .script_pubkey()
            .ok_or(WalletOutputError::UnknownScriptVariant)?;

        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: wallet.outpoint,
                script_sig: Default::default(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: change_value,
                    script_pubkey: self.descriptor(&wallet.consensus_hash()).script_pubkey(),
                },
                TxOut {
                    value: output.value,
                    script_pubkey,
                },
            ],
        };

        dbtx.insert_new_entry(
            &FederationWalletKey,
            &FederationWallet {
                value: change_value,
                outpoint: bitcoin::OutPoint {
                    txid: tx.compute_txid(),
                    vout: 0,
                },
                tweak: wallet.consensus_hash(),
            },
        )
        .await;

        let tx_index = self.total_txs(dbtx).await;

        let created = self.consensus_block_count(dbtx).await;

        dbtx.insert_new_entry(
            &TxInfoKey(tx_index),
            &TxInfo {
                index: tx_index,
                txid: tx.compute_txid(),
                input: wallet.value,
                output: change_value,
                vbytes: self.cfg.consensus.send_tx_vbytes,
                fee: output.fee,
                created,
            },
        )
        .await;

        dbtx.insert_new_entry(&TxInfoIndexKey(outpoint), &tx_index)
            .await;

        dbtx.insert_new_entry(
            &UnsignedTxKey(tx.compute_txid()),
            &FederationTx {
                tx,
                spent_tx_outs: vec![SpentTxOut {
                    value: wallet.value,
                    tweak: wallet.tweak,
                }],
                vbytes: self.cfg.consensus.send_tx_vbytes,
                fee: output.fee,
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
                |_, wallet| 1000 * wallet.value.to_sat() as i64,
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
                    Ok(module.tx_id(&mut dbtx, params).await)
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
                async |module: &Wallet, context, _params: ()| -> Vec<TxInfo> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.pending_tx_chain(&mut dbtx).await)
                }
            },
            api_endpoint! {
                TRANSACTION_CHAIN_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, params: usize| -> Vec<TxInfo> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.tx_chain(&mut dbtx, params).await)
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
        Self::spawn_broadcast_unconfirmed_txs_task(btc_rpc.clone(), db.clone(), task_group);

        Wallet {
            cfg,
            btc_rpc,
            db: db.clone(),
        }
    }

    fn spawn_broadcast_unconfirmed_txs_task(
        btc_rpc: ServerBitcoinRpcMonitor,
        db: Database,
        task_group: &TaskGroup,
    ) {
        task_group.spawn_cancellable("broadcast_unconfirmed_transactions", async move {
            loop {
                let unconfirmed_txs = db
                    .begin_transaction_nc()
                    .await
                    .find_by_prefix(&UnconfirmedTxPrefix)
                    .await
                    .map(|entry| entry.1)
                    .collect::<Vec<FederationTx>>()
                    .await;

                for unconfirmed_tx in unconfirmed_txs {
                    btc_rpc.submit_transaction(unconfirmed_tx.tx).await;
                }

                sleep(common::sleep_duration()).await;
            }
        });
    }

    async fn process_block_count(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        block_count_vote: u64,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        let old_consensus_block_count = self.consensus_block_count(dbtx).await;

        let current_vote = dbtx
            .insert_entry(&BlockCountVoteKey(peer), &block_count_vote)
            .await
            .unwrap_or(0);

        ensure!(
            current_vote < block_count_vote,
            "Block count vote is redundant"
        );

        let new_consensus_block_count = self.consensus_block_count(dbtx).await;

        assert!(old_consensus_block_count <= new_consensus_block_count);

        // We do not sync blocks that predate the federation itself.
        if old_consensus_block_count == 0 {
            return Ok(());
        }

        // Our bitcoin backend needs to be synced for the following calls to the
        // get_block rpc to be safe for consensus.
        self.await_local_sync_to_block_count(
            new_consensus_block_count + CONFIRMATION_FINALITY_DELAY,
        )
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

            assert_eq!(block.block_hash(), block_hash, "Block hash mismatch");

            let pks_hash = self.cfg.consensus.bitcoin_pks.consensus_hash();

            for tx in block.txdata {
                dbtx.remove_entry(&UnconfirmedTxKey(tx.compute_txid()))
                    .await;

                // We maintain an append-only log of valid P2WSH transaction outputs created
                // since the federation was established. This is downloaded by clients to
                // detect pegins and claim them by index.

                for (vout, tx_out) in tx.output.iter().enumerate() {
                    if is_potential_receive(&tx_out.script_pubkey, &pks_hash)
                        && tx_out.script_pubkey.is_p2wsh()
                    {
                        let outpoint = bitcoin::OutPoint {
                            txid: tx.compute_txid(),
                            vout: u32::try_from(vout)
                                .expect("Bitcoin transaction has more than u32::MAX outputs"),
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

        Ok(())
    }

    async fn process_signatures(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        txid: bitcoin::Txid,
        signatures: Vec<Signature>,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        let mut unsigned = dbtx
            .get_value(&UnsignedTxKey(txid))
            .await
            .context("Unsigned transaction does not exist")?;

        let pk = self
            .cfg
            .consensus
            .bitcoin_pks
            .get(&peer)
            .expect("Failed to get public key of peer from config");

        self.verify_signatures(&unsigned, &signatures, *pk)?;

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
            dbtx.remove_entry(&UnsignedTxKey(txid)).await;

            dbtx.remove_by_prefix(&SignaturesTxidPrefix(txid)).await;

            self.finalize_tx(&mut unsigned, &signatures);

            dbtx.insert_new_entry(&UnconfirmedTxKey(txid), &unsigned)
                .await;

            self.btc_rpc.submit_transaction(unsigned.tx).await;
        }

        Ok(())
    }

    async fn await_local_sync_to_block_count(&self, block_count: u64) {
        loop {
            if self
                .btc_rpc
                .status()
                .is_some_and(|status| status.block_count >= block_count)
            {
                break;
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

    pub async fn consensus_fee(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        tx_vbytes: u64,
    ) -> Option<Amount> {
        // The minimum feerate is a protection against a catastrophic error in the
        // feerate estimation and limits the length of the pending transaction stack.

        let pending_txs = pending_txs_unordered(dbtx).await;

        assert!(pending_txs.len() <= 32);

        let feerate = self
            .consensus_feerate(dbtx)
            .await?
            .max(self.cfg.consensus.min_feerate << pending_txs.len());

        let tx_fee = tx_vbytes.saturating_mul(feerate).saturating_div(1000);

        let stack_vbytes = pending_txs
            .iter()
            .map(|t| t.vbytes)
            .try_fold(tx_vbytes, u64::checked_add)
            .expect("Stack vbytes overflow with at most 32 pending txs");

        let stack_fee = stack_vbytes.saturating_mul(feerate).saturating_div(1000);

        // Deduct the fees already paid by currently pending transactions
        let stack_fee = pending_txs
            .iter()
            .map(|t| t.fee.to_sat())
            .fold(stack_fee, u64::saturating_sub);

        Some(Amount::from_sat(tx_fee.max(stack_fee)))
    }

    pub async fn send_fee(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<Amount> {
        self.consensus_fee(dbtx, self.cfg.consensus.send_tx_vbytes)
            .await
    }

    pub async fn receive_fee(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<Amount> {
        self.consensus_fee(dbtx, self.cfg.consensus.receive_tx_vbytes)
            .await
    }

    fn descriptor(&self, tweak: &sha256::Hash) -> Wsh<secp256k1::PublicKey> {
        descriptor(&self.cfg.consensus.bitcoin_pks, tweak)
    }

    fn sign_tx(&self, unsigned_tx: &FederationTx) -> Vec<Signature> {
        let mut sighash_cache = SighashCache::new(unsigned_tx.tx.clone());

        unsigned_tx
            .spent_tx_outs
            .iter()
            .enumerate()
            .map(|(index, utxo)| {
                let descriptor = self.descriptor(&utxo.tweak).ecdsa_sighash_script_code();

                let p2wsh_sighash = sighash_cache
                    .p2wsh_signature_hash(index, &descriptor, utxo.value, EcdsaSighashType::All)
                    .expect("Failed to compute P2WSH segwit sighash");

                let scalar = &Scalar::from_be_bytes(utxo.tweak.to_byte_array())
                    .expect("Hash is within field order");

                let sk = self
                    .cfg
                    .private
                    .bitcoin_sk
                    .add_tweak(scalar)
                    .expect("Failed to tweak bitcoin secret key");

                Secp256k1::new().sign_ecdsa(&p2wsh_sighash.into(), &sk)
            })
            .collect()
    }

    fn verify_signatures(
        &self,
        unsigned_tx: &FederationTx,
        signatures: &[Signature],
        pk: PublicKey,
    ) -> anyhow::Result<()> {
        ensure!(
            unsigned_tx.spent_tx_outs.len() == signatures.len(),
            "Incorrect number of signatures"
        );

        let mut sighash_cache = SighashCache::new(unsigned_tx.tx.clone());

        for ((index, utxo), signature) in unsigned_tx
            .spent_tx_outs
            .iter()
            .enumerate()
            .zip(signatures.iter())
        {
            let descriptor = self.descriptor(&utxo.tweak).ecdsa_sighash_script_code();

            let p2wsh_sighash = sighash_cache
                .p2wsh_signature_hash(index, &descriptor, utxo.value, EcdsaSighashType::All)
                .expect("Failed to compute P2WSH segwit sighash");

            let pk = tweak_public_key(&pk, &utxo.tweak);

            secp256k1::SECP256K1.verify_ecdsa(&p2wsh_sighash.into(), signature, &pk)?;
        }

        Ok(())
    }

    fn finalize_tx(
        &self,
        federation_tx: &mut FederationTx,
        signatures: &BTreeMap<PeerId, Vec<Signature>>,
    ) {
        assert_eq!(
            federation_tx.spent_tx_outs.len(),
            federation_tx.tx.input.len()
        );

        for (index, utxo) in federation_tx.spent_tx_outs.iter().enumerate() {
            let satisfier: BTreeMap<PublicKey, bitcoin::ecdsa::Signature> = signatures
                .iter()
                .map(|(peer, sigs)| {
                    assert_eq!(sigs.len(), federation_tx.tx.input.len());

                    let pk = *self
                        .cfg
                        .consensus
                        .bitcoin_pks
                        .get(peer)
                        .expect("Failed to get public key of peer from config");

                    let pk = tweak_public_key(&pk, &utxo.tweak);

                    (pk, bitcoin::ecdsa::Signature::sighash_all(sigs[index]))
                })
                .collect();

            miniscript::Descriptor::Wsh(self.descriptor(&utxo.tweak))
                .satisfy(&mut federation_tx.tx.input[index], satisfier)
                .expect("Failed to satisfy descriptor");
        }
    }

    async fn tx_id(&self, dbtx: &mut DatabaseTransaction<'_>, outpoint: OutPoint) -> Option<Txid> {
        let index = dbtx.get_value(&TxInfoIndexKey(outpoint)).await?;

        dbtx.get_value(&TxInfoKey(index))
            .await
            .map(|entry| entry.txid)
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

    async fn pending_tx_chain(&self, dbtx: &mut DatabaseTransaction<'_>) -> Vec<TxInfo> {
        let n_pending = pending_txs_unordered(dbtx).await.len();

        dbtx.find_by_prefix_sorted_descending(&TxInfoPrefix)
            .await
            .take(n_pending)
            .map(|entry| entry.1)
            .collect()
            .await
    }

    async fn tx_chain(&self, dbtx: &mut DatabaseTransaction<'_>, n: usize) -> Vec<TxInfo> {
        dbtx.find_by_prefix_sorted_descending(&TxInfoPrefix)
            .await
            .take(n)
            .map(|entry| entry.1)
            .collect()
            .await
    }

    async fn total_txs(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        dbtx.find_by_prefix_sorted_descending(&TxInfoPrefix)
            .await
            .next()
            .await
            .map_or(0, |entry| entry.0.0 + 1)
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
    pub async fn pending_tx_chain_ui(&self) -> Vec<TxInfo> {
        self.pending_tx_chain(&mut self.db.begin_transaction_nc().await)
            .await
    }

    /// Get the current transaction log for UI display
    pub async fn tx_chain_ui(&self, n: usize) -> Vec<TxInfo> {
        self.tx_chain(&mut self.db.begin_transaction_nc().await, n)
            .await
    }

    /// Export recovery keys for federation shutdown. Returns None if the
    /// federation wallet has not been initialized yet.
    pub async fn recovery_keys_ui(&self) -> Option<(BTreeMap<PeerId, String>, String)> {
        let wallet = self.federation_wallet_ui().await?;

        let pks = self
            .cfg
            .consensus
            .bitcoin_pks
            .iter()
            .map(|(peer, pk)| (*peer, tweak_public_key(pk, &wallet.tweak).to_string()))
            .collect();

        let tweak = &Scalar::from_be_bytes(wallet.tweak.to_byte_array())
            .expect("Hash is within field order");

        let sk = self
            .cfg
            .private
            .bitcoin_sk
            .add_tweak(tweak)
            .expect("Failed to tweak bitcoin secret key");

        let sk = bitcoin::PrivateKey::new(sk, self.cfg.consensus.network).to_wif();

        Some((pks, sk))
    }
}

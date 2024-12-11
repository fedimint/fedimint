#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]

pub mod db;
mod feerate_source;

use std::clone::Clone;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::Infallible;
use std::iter;
use std::sync::Arc;
#[cfg(not(target_family = "wasm"))]
use std::time::Duration;

use anyhow::{bail, ensure, format_err, Context};
use bitcoin::absolute::LockTime;
use bitcoin::address::NetworkUnchecked;
use bitcoin::ecdsa::Signature as EcdsaSig;
use bitcoin::hashes::{sha256, Hash as BitcoinHash, HashEngine, Hmac, HmacEngine};
use bitcoin::policy::DEFAULT_MIN_RELAY_TX_FEE;
use bitcoin::psbt::{Input, Psbt};
use bitcoin::secp256k1::{self, All, Message, Scalar, Secp256k1, Verification};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Address, BlockHash, Network, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};
use common::config::WalletConfigConsensus;
use common::{
    proprietary_tweak_key, PegOutFees, PegOutSignatureItem, ProcessPegOutSigError, SpendableUTXO,
    TxOutputSummary, WalletCommonInit, WalletConsensusItem, WalletCreationError, WalletInput,
    WalletModuleTypes, WalletOutput, WalletOutputOutcome, WalletSummary, DEPRECATED_RBF_ERROR,
    FEERATE_MULTIPLIER,
};
use fedimint_bitcoind::{create_bitcoind, DynBitcoindRpc};
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, ServerModuleConfig, ServerModuleConsensusConfig,
    TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    CoreMigrationFn, Database, DatabaseTransaction, DatabaseVersion,
    IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::btc::NetworkLegacyEncodingWrapper;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::{
    is_rbf_withdrawal_enabled, is_running_in_test_env, BitcoinRpcConfig,
    FM_WALLET_FEERATE_SOURCES_ENV,
};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ApiError, ApiVersion, CoreConsensusVersion, InputMeta,
    ModuleConsensusVersion, ModuleInit, PeerHandle, ServerModuleInit, ServerModuleInitArgs,
    SupportedModuleApiVersions, TransactionItemAmount, CORE_CONSENSUS_VERSION,
};
use fedimint_core::server::DynServerModule;
#[cfg(not(target_family = "wasm"))]
use fedimint_core::task::sleep;
use fedimint_core::task::{TaskGroup, TaskHandle};
use fedimint_core::time::now;
use fedimint_core::util::{backoff_util, retry};
use fedimint_core::{
    apply, async_trait_maybe_send, get_network_for_address, push_db_key_items, push_db_pair_items,
    Feerate, NumPeersExt, OutPoint, PeerId, ServerModule,
};
use fedimint_logging::LOG_MODULE_WALLET;
use fedimint_server::config::distributedgen::PeerHandleOps;
use fedimint_server::net::api::check_auth;
pub use fedimint_wallet_common as common;
use fedimint_wallet_common::config::{WalletClientConfig, WalletConfig, WalletGenParams};
use fedimint_wallet_common::endpoint_constants::{
    ACTIVATE_CONSENSUS_VERSION_VOTING_ENDPOINT, BITCOIN_KIND_ENDPOINT, BITCOIN_RPC_CONFIG_ENDPOINT,
    BLOCK_COUNT_ENDPOINT, BLOCK_COUNT_LOCAL_ENDPOINT, MODULE_CONSENSUS_VERSION_ENDPOINT,
    PEG_OUT_FEES_ENDPOINT, WALLET_SUMMARY_ENDPOINT,
};
use fedimint_wallet_common::keys::CompressedPublicKey;
use fedimint_wallet_common::tweakable::Tweakable;
use fedimint_wallet_common::{
    Rbf, UnknownWalletInputVariantError, WalletInputError, WalletOutputError, WalletOutputV0,
    MODULE_CONSENSUS_VERSION,
};
use feerate_source::{FeeRateSource, FetchJson};
use futures::{FutureExt, StreamExt};
use metrics::{
    WALLET_INOUT_FEES_SATS, WALLET_INOUT_SATS, WALLET_PEGIN_FEES_SATS, WALLET_PEGIN_SATS,
    WALLET_PEGOUT_FEES_SATS, WALLET_PEGOUT_SATS,
};
use miniscript::psbt::PsbtExt;
use miniscript::{translate_hash_fail, Descriptor, TranslatePk};
use rand::rngs::OsRng;
use serde::Serialize;
use strum::IntoEnumIterator;
use tokio::sync::watch;
use tracing::{debug, info, instrument, trace, warn};

use crate::db::{
    migrate_to_v1, BlockCountVoteKey, BlockCountVotePrefix, BlockHashKey, BlockHashKeyPrefix,
    ClaimedPegInOutpointKey, ClaimedPegInOutpointPrefixKey, ConsensusVersionVoteKey,
    ConsensusVersionVotePrefix, ConsensusVersionVotingActivationKey,
    ConsensusVersionVotingActivationPrefix, DbKeyPrefix, FeeRateVoteKey, FeeRateVotePrefix,
    PegOutBitcoinTransaction, PegOutBitcoinTransactionPrefix, PegOutNonceKey, PegOutTxSignatureCI,
    PegOutTxSignatureCIPrefix, PendingTransactionKey, PendingTransactionPrefixKey, UTXOKey,
    UTXOPrefixKey, UnsignedTransactionKey, UnsignedTransactionPrefixKey, UnspentTxOutKey,
    UnspentTxOutPrefix,
};
use crate::metrics::WALLET_BLOCK_COUNT;

mod metrics;

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
                DbKeyPrefix::BlockHash => {
                    push_db_key_items!(dbtx, BlockHashKeyPrefix, BlockHashKey, wallet, "Blocks");
                }
                DbKeyPrefix::PegOutBitcoinOutPoint => {
                    push_db_pair_items!(
                        dbtx,
                        PegOutBitcoinTransactionPrefix,
                        PegOutBitcoinTransaction,
                        WalletOutputOutcome,
                        wallet,
                        "Peg Out Bitcoin Transaction"
                    );
                }
                DbKeyPrefix::PegOutTxSigCi => {
                    push_db_pair_items!(
                        dbtx,
                        PegOutTxSignatureCIPrefix,
                        PegOutTxSignatureCI,
                        Vec<secp256k1::ecdsa::Signature>,
                        wallet,
                        "Peg Out Transaction Signatures"
                    );
                }
                DbKeyPrefix::PendingTransaction => {
                    push_db_pair_items!(
                        dbtx,
                        PendingTransactionPrefixKey,
                        PendingTransactionKey,
                        PendingTransaction,
                        wallet,
                        "Pending Transactions"
                    );
                }
                DbKeyPrefix::PegOutNonce => {
                    if let Some(nonce) = dbtx.get_value(&PegOutNonceKey).await {
                        wallet.insert("Peg Out Nonce".to_string(), Box::new(nonce));
                    }
                }
                DbKeyPrefix::UnsignedTransaction => {
                    push_db_pair_items!(
                        dbtx,
                        UnsignedTransactionPrefixKey,
                        UnsignedTransactionKey,
                        UnsignedTransaction,
                        wallet,
                        "Unsigned Transactions"
                    );
                }
                DbKeyPrefix::Utxo => {
                    push_db_pair_items!(
                        dbtx,
                        UTXOPrefixKey,
                        UTXOKey,
                        SpendableUTXO,
                        wallet,
                        "UTXOs"
                    );
                }
                DbKeyPrefix::BlockCountVote => {
                    push_db_pair_items!(
                        dbtx,
                        BlockCountVotePrefix,
                        BlockCountVoteKey,
                        u32,
                        wallet,
                        "Block Count Votes"
                    );
                }
                DbKeyPrefix::FeeRateVote => {
                    push_db_pair_items!(
                        dbtx,
                        FeeRateVotePrefix,
                        FeeRateVoteKey,
                        Feerate,
                        wallet,
                        "Fee Rate Votes"
                    );
                }
                DbKeyPrefix::ClaimedPegInOutpoint => {
                    push_db_pair_items!(
                        dbtx,
                        ClaimedPegInOutpointPrefixKey,
                        PeggedInOutpointKey,
                        (),
                        wallet,
                        "Claimed Peg-in Outpoint"
                    );
                }
                DbKeyPrefix::ConsensusVersionVote => {
                    push_db_pair_items!(
                        dbtx,
                        ConsensusVersionVotePrefix,
                        ConsensusVersionVoteKey,
                        ModuleConsensusVersion,
                        wallet,
                        "Consensus Version Votes"
                    );
                }
                DbKeyPrefix::UnspentTxOut => {
                    push_db_pair_items!(
                        dbtx,
                        UnspentTxOutPrefix,
                        UnspentTxOutKey,
                        TxOut,
                        wallet,
                        "Consensus Version Votes"
                    );
                }
                DbKeyPrefix::ConsensusVersionVotingActivation => {
                    push_db_pair_items!(
                        dbtx,
                        ConsensusVersionVotingActivationPrefix,
                        ConsensusVersionVotingActivationKey,
                        (),
                        wallet,
                        "Consensus Version Voting Activation Key"
                    );
                }
            }
        }

        Box::new(wallet.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleInit for WalletInit {
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

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule> {
        for direction in ["incoming", "outgoing"] {
            WALLET_INOUT_FEES_SATS
                .with_label_values(&[direction])
                .get_sample_count();
            WALLET_INOUT_SATS
                .with_label_values(&[direction])
                .get_sample_count();
        }
        // Eagerly initialize metrics that trigger infrequently
        WALLET_PEGIN_FEES_SATS.get_sample_count();
        WALLET_PEGIN_SATS.get_sample_count();
        WALLET_PEGOUT_SATS.get_sample_count();
        WALLET_PEGOUT_FEES_SATS.get_sample_count();

        Ok(Wallet::new(
            args.cfg().to_typed()?,
            args.db(),
            args.task_group(),
            args.our_peer_id(),
        )
        .await?
        .into())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();

        let btc_pegin_keys = peers
            .iter()
            .map(|&id| (id, secp.generate_keypair(&mut OsRng)))
            .collect::<Vec<_>>();

        let wallet_cfg: BTreeMap<PeerId, WalletConfig> = btc_pegin_keys
            .iter()
            .map(|(id, (sk, _))| {
                let cfg = WalletConfig::new(
                    btc_pegin_keys
                        .iter()
                        .map(|(peer_id, (_, pk))| (*peer_id, CompressedPublicKey { key: *pk }))
                        .collect(),
                    *sk,
                    peers.to_num_peers().threshold(),
                    params.consensus.network,
                    params.consensus.finality_delay,
                    params.local.bitcoin_rpc.clone(),
                    params.consensus.client_default_bitcoin_rpc.clone(),
                    params.consensus.fee_consensus,
                );
                (*id, cfg)
            })
            .collect();

        wallet_cfg
            .into_iter()
            .map(|(k, v)| (k, v.to_erased()))
            .collect()
    }

    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        let params = self.parse_params(params).unwrap();
        let secp = secp256k1::Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut OsRng);
        let our_key = CompressedPublicKey { key: pk };
        let peer_peg_in_keys: BTreeMap<PeerId, CompressedPublicKey> = peers
            .exchange_pubkeys("wallet".to_string(), our_key.key)
            .await?
            .into_iter()
            .map(|(k, key)| (k, CompressedPublicKey { key }))
            .collect();

        let wallet_cfg = WalletConfig::new(
            peer_peg_in_keys,
            sk,
            peers.peer_ids().to_num_peers().threshold(),
            params.consensus.network,
            params.consensus.finality_delay,
            params.local.bitcoin_rpc.clone(),
            params.consensus.client_default_bitcoin_rpc.clone(),
            params.consensus.fee_consensus,
        );

        Ok(wallet_cfg.to_erased())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<WalletConfig>()?;
        let pubkey = secp256k1::PublicKey::from_secret_key_global(&config.private.peg_in_key);

        if config
            .consensus
            .peer_peg_in_keys
            .get(identity)
            .ok_or_else(|| format_err!("Secret key doesn't match any public key"))?
            != &CompressedPublicKey::new(pubkey)
        {
            bail!(" Bitcoin wallet private key doesn't match multisig pubkey");
        }

        Ok(())
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<WalletClientConfig> {
        let config = WalletConfigConsensus::from_erased(config)?;
        Ok(WalletClientConfig {
            peg_in_descriptor: config.peg_in_descriptor,
            network: config.network,
            fee_consensus: config.fee_consensus,
            finality_delay: config.finality_delay,
            default_bitcoin_rpc: config.client_default_bitcoin_rpc,
        })
    }

    /// DB migrations to move from old to newer versions
    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, CoreMigrationFn> {
        let mut migrations: BTreeMap<DatabaseVersion, CoreMigrationFn> = BTreeMap::new();
        migrations.insert(DatabaseVersion(0), |ctx| migrate_to_v1(ctx).boxed());
        migrations
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
            .find_by_prefix(&PegOutTxSignatureCIPrefix)
            .await
            .map(|(key, val)| {
                WalletConsensusItem::PegOutSignature(PegOutSignatureItem {
                    txid: key.0,
                    signature: val,
                })
            })
            .collect::<Vec<WalletConsensusItem>>()
            .await;

        // If we are unable to get a block count from the node we skip adding a block
        // count vote to consensus items.
        //
        // The potential impact of not including the latest block count from our peer's
        // node is delayed processing of change outputs for the federation, which is an
        // acceptable risk since subsequent rounds of consensus will reattempt to fetch
        // the latest block count.
        match self.get_block_count() {
            Ok(block_count) => {
                let block_count_vote =
                    block_count.saturating_sub(self.cfg.consensus.finality_delay);

                let current_vote = dbtx
                    .get_value(&BlockCountVoteKey(self.our_peer_id))
                    .await
                    .unwrap_or(0);

                debug!(
                    target: LOG_MODULE_WALLET,
                    ?current_vote,
                    ?block_count_vote,
                    ?block_count,
                    "Proposing block count"
                );

                WALLET_BLOCK_COUNT.set(i64::from(block_count_vote));
                items.push(WalletConsensusItem::BlockCount(block_count_vote));
            }
            Err(err) => {
                warn!(target: LOG_MODULE_WALLET, %err, "Can't update block count");
            }
        }

        let fee_rate_proposal = self.get_fee_rate_opt();

        items.push(WalletConsensusItem::Feerate(fee_rate_proposal));

        if dbtx
            .get_value(&ConsensusVersionVotingActivationKey)
            .await
            .is_some()
            || is_running_in_test_env()
        {
            items.push(WalletConsensusItem::ModuleConsensusVersion(
                MODULE_CONSENSUS_VERSION,
            ));
        }

        items
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: WalletConsensusItem,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        trace!(?consensus_item, "Received consensus proposals");

        match consensus_item {
            WalletConsensusItem::BlockCount(block_count_vote) => {
                debug!(?peer, ?block_count_vote, "Received block count vote");

                let current_vote = dbtx.get_value(&BlockCountVoteKey(peer)).await.unwrap_or(0);

                if block_count_vote < current_vote {
                    warn!(target: LOG_MODULE_WALLET, ?peer, ?block_count_vote, "Block count vote is outdated");
                }

                ensure!(
                    block_count_vote > current_vote,
                    "Block count vote is redundant"
                );

                let old_consensus_block_count = self.consensus_block_count(dbtx).await;

                dbtx.insert_entry(&BlockCountVoteKey(peer), &block_count_vote)
                    .await;

                let new_consensus_block_count = self.consensus_block_count(dbtx).await;

                debug!(
                    ?peer,
                    ?current_vote,
                    ?block_count_vote,
                    ?old_consensus_block_count,
                    ?new_consensus_block_count,
                    "Received block count vote"
                );

                assert!(old_consensus_block_count <= new_consensus_block_count);

                if new_consensus_block_count != old_consensus_block_count {
                    // We do not sync blocks that predate the federation itself
                    if old_consensus_block_count != 0 {
                        self.sync_up_to_consensus_count(
                            dbtx,
                            old_consensus_block_count,
                            new_consensus_block_count,
                        )
                        .await;
                    } else {
                        info!(
                            target: LOG_MODULE_WALLET,
                            ?old_consensus_block_count,
                            ?new_consensus_block_count,
                            "Not syncing up to consensus block count because we are at block 0"
                        );
                    }
                }
            }
            WalletConsensusItem::Feerate(feerate) => {
                if Some(feerate) == dbtx.insert_entry(&FeeRateVoteKey(peer), &feerate).await {
                    bail!("Fee rate vote is redundant");
                }
            }
            WalletConsensusItem::PegOutSignature(peg_out_signature) => {
                let txid = peg_out_signature.txid;

                if dbtx.get_value(&PendingTransactionKey(txid)).await.is_some() {
                    bail!("Already received a threshold of valid signatures");
                }

                let mut unsigned = dbtx
                    .get_value(&UnsignedTransactionKey(txid))
                    .await
                    .context("Unsigned transaction does not exist")?;

                self.sign_peg_out_psbt(&mut unsigned.psbt, peer, &peg_out_signature)
                    .context("Peg out signature is invalid")?;

                dbtx.insert_entry(&UnsignedTransactionKey(txid), &unsigned)
                    .await;

                if let Ok(pending_tx) = self.finalize_peg_out_psbt(unsigned) {
                    // We were able to finalize the transaction, so we will delete the
                    // PSBT and instead keep the extracted tx for periodic transmission
                    // as well as to accept the change into our wallet eventually once
                    // it confirms.
                    dbtx.insert_new_entry(&PendingTransactionKey(txid), &pending_tx)
                        .await;

                    dbtx.remove_entry(&PegOutTxSignatureCI(txid)).await;
                    dbtx.remove_entry(&UnsignedTransactionKey(txid)).await;
                }
            }
            WalletConsensusItem::ModuleConsensusVersion(module_consensus_version) => {
                let current_vote = dbtx
                    .get_value(&ConsensusVersionVoteKey(peer))
                    .await
                    .unwrap_or(ModuleConsensusVersion::new(2, 0));

                ensure!(
                    module_consensus_version > current_vote,
                    "Module consensus version vote is redundant"
                );

                dbtx.insert_entry(&ConsensusVersionVoteKey(peer), &module_consensus_version)
                    .await;

                assert!(
                    self.consensus_module_consensus_version(dbtx).await <= MODULE_CONSENSUS_VERSION,
                    "Wallet module does not support new consensus version, please upgrade the module"
                );
            }
            WalletConsensusItem::Default { variant, .. } => {
                panic!("Received wallet consensus item with unknown variant {variant}");
            }
        }

        Ok(())
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b WalletInput,
    ) -> Result<InputMeta, WalletInputError> {
        let (outpoint, value, pub_key) = match input {
            WalletInput::V0(input) => {
                if !self.block_is_known(dbtx, input.proof_block()).await {
                    return Err(WalletInputError::UnknownPegInProofBlock(
                        input.proof_block(),
                    ));
                }

                input.verify(&self.secp, &self.cfg.consensus.peg_in_descriptor)?;

                debug!(outpoint = %input.outpoint(), "Claiming peg-in");

                (
                    input.0.outpoint(),
                    input.tx_output().value,
                    *input.tweak_contract_key(),
                )
            }
            WalletInput::V1(input) => {
                let input_tx_out = dbtx
                    .get_value(&UnspentTxOutKey(input.outpoint))
                    .await
                    .ok_or(WalletInputError::UnknownUTXO)?;

                if input_tx_out.script_pubkey
                    != self
                        .cfg
                        .consensus
                        .peg_in_descriptor
                        .tweak(&input.tweak_contract_key, secp256k1::SECP256K1)
                        .script_pubkey()
                {
                    return Err(WalletInputError::WrongOutputScript);
                }

                // Verifying this is not strictly necessary for the server as the tx_out is only
                // used in backup and recovery.
                if input.tx_out != input_tx_out {
                    return Err(WalletInputError::WrongTxOut);
                }

                (input.outpoint, input_tx_out.value, input.tweak_contract_key)
            }
            WalletInput::Default { variant, .. } => {
                return Err(WalletInputError::UnknownInputVariant(
                    UnknownWalletInputVariantError { variant: *variant },
                ));
            }
        };

        if dbtx
            .insert_entry(&ClaimedPegInOutpointKey(outpoint), &())
            .await
            .is_some()
        {
            return Err(WalletInputError::PegInAlreadyClaimed);
        }

        dbtx.insert_new_entry(
            &UTXOKey(outpoint),
            &SpendableUTXO {
                tweak: pub_key.serialize(),
                amount: value,
            },
        )
        .await;

        let amount = value.into();

        let fee = self.cfg.consensus.fee_consensus.peg_in_abs;

        calculate_pegin_metrics(dbtx, amount, fee);

        Ok(InputMeta {
            amount: TransactionItemAmount { amount, fee },
            pub_key,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a WalletOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmount, WalletOutputError> {
        let output = output.ensure_v0_ref()?;

        // In 0.4.0 we began preventing RBF withdrawals. Once we reach EoL support
        // for 0.4.0, we can safely remove RBF withdrawal logic.
        // see: https://github.com/fedimint/fedimint/issues/5453
        if let WalletOutputV0::Rbf(_) = output {
            // This exists as an escape hatch for any federations that successfully
            // processed an RBF withdrawal due to having a single UTXO owned by the
            // federation. If a peer needs to resync the federation's history, they can
            // enable this variable until they've successfully synced, then restart with
            // this disabled.
            if is_rbf_withdrawal_enabled() {
                warn!(target: LOG_MODULE_WALLET, "processing rbf withdrawal");
            } else {
                return Err(DEPRECATED_RBF_ERROR);
            }
        }

        let change_tweak = self.consensus_nonce(dbtx).await;

        let mut tx = self.create_peg_out_tx(dbtx, output, &change_tweak).await?;

        let fee_rate = self.consensus_fee_rate(dbtx).await;

        StatelessWallet::validate_tx(&tx, output, fee_rate, self.cfg.consensus.network.0)?;

        self.offline_wallet().sign_psbt(&mut tx.psbt);

        let txid = tx.psbt.unsigned_tx.compute_txid();

        info!(
            target: LOG_MODULE_WALLET,
            %txid,
            "Signing peg out",
        );

        let sigs = tx
            .psbt
            .inputs
            .iter_mut()
            .map(|input| {
                assert_eq!(
                    input.partial_sigs.len(),
                    1,
                    "There was already more than one (our) or no signatures in input"
                );

                // TODO: don't put sig into PSBT in the first place
                // We actually take out our own signature so everyone finalizes the tx in the
                // same epoch.
                let sig = std::mem::take(&mut input.partial_sigs)
                    .into_values()
                    .next()
                    .expect("asserted previously");

                // We drop SIGHASH_ALL, because we always use that and it is only present in the
                // PSBT for compatibility with other tools.
                secp256k1::ecdsa::Signature::from_der(&sig.to_vec()[..sig.to_vec().len() - 1])
                    .expect("we serialized it ourselves that way")
            })
            .collect::<Vec<_>>();

        // Delete used UTXOs
        for input in &tx.psbt.unsigned_tx.input {
            dbtx.remove_entry(&UTXOKey(input.previous_output)).await;
        }

        dbtx.insert_new_entry(&UnsignedTransactionKey(txid), &tx)
            .await;

        dbtx.insert_new_entry(&PegOutTxSignatureCI(txid), &sigs)
            .await;

        dbtx.insert_new_entry(
            &PegOutBitcoinTransaction(out_point),
            &WalletOutputOutcome::new_v0(txid),
        )
        .await;
        let amount: fedimint_core::Amount = output.amount().into();
        let fee = self.cfg.consensus.fee_consensus.peg_out_abs;
        calculate_pegout_metrics(dbtx, amount, fee);
        Ok(TransactionItemAmount { amount, fee })
    }

    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<WalletOutputOutcome> {
        dbtx.get_value(&PegOutBitcoinTransaction(out_point)).await
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        audit
            .add_items(dbtx, module_instance_id, &UTXOPrefixKey, |_, v| {
                v.amount.to_sat() as i64 * 1000
            })
            .await;
        audit
            .add_items(
                dbtx,
                module_instance_id,
                &UnsignedTransactionPrefixKey,
                |_, v| match v.rbf {
                    None => v.change.to_sat() as i64 * 1000,
                    Some(rbf) => rbf.fees.amount().to_sat() as i64 * -1000,
                },
            )
            .await;
        audit
            .add_items(
                dbtx,
                module_instance_id,
                &PendingTransactionPrefixKey,
                |_, v| match v.rbf {
                    None => v.change.to_sat() as i64 * 1000,
                    Some(rbf) => rbf.fees.amount().to_sat() as i64 * -1000,
                },
            )
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                MODULE_CONSENSUS_VERSION_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> ModuleConsensusVersion {
                    Ok(module.consensus_module_consensus_version(&mut context.dbtx().into_nc()).await)
                }
            },
            api_endpoint! {
                ACTIVATE_CONSENSUS_VERSION_VOTING_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Wallet, context, _params: ()| -> () {
                    check_auth(context)?;

                    let mut dbtx = context.dbtx();

                    dbtx.insert_entry(&ConsensusVersionVotingActivationKey, &()).await;

                    dbtx.commit_tx_result().await.map_err(|e| ApiError::server_error(e.to_string()))?;

                    Ok(())

                }
            },
            api_endpoint! {
                BLOCK_COUNT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> u32 {
                    Ok(module.consensus_block_count(&mut context.dbtx().into_nc()).await)
                }
            },
            api_endpoint! {
                BLOCK_COUNT_LOCAL_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, _context, _params: ()| -> Option<u32> {
                    Ok(module.get_block_count().ok())
                }
            },
            api_endpoint! {
                PEG_OUT_FEES_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, params: (Address<NetworkUnchecked>, u64)| -> Option<PegOutFees> {
                    let (address, sats) = params;
                    let feerate = module.consensus_fee_rate(&mut context.dbtx().into_nc()).await;

                    // Since we are only calculating the tx size we can use an arbitrary dummy nonce.
                    let dummy_tweak = [0; 33];

                    let tx = module.offline_wallet().create_tx(
                        bitcoin::Amount::from_sat(sats),
                        address.assume_checked().script_pubkey(),
                        vec![],
                        module.available_utxos(&mut context.dbtx().into_nc()).await,
                        feerate,
                        &dummy_tweak,
                        None
                    );

                    match tx {
                        Err(error) => {
                            // Usually from not enough spendable UTXOs
                            warn!(target: LOG_MODULE_WALLET, "Error returning peg-out fees {error}");
                            Ok(None)
                        }
                        Ok(tx) => Ok(Some(tx.fees))
                    }
                }
            },
            api_endpoint! {
                BITCOIN_KIND_ENDPOINT,
                ApiVersion::new(0, 1),
                async |module: &Wallet, _context, _params: ()| -> String {
                    Ok(module.btc_rpc.get_bitcoin_rpc_config().kind)
                }
            },
            api_endpoint! {
                BITCOIN_RPC_CONFIG_ENDPOINT,
                ApiVersion::new(0, 1),
                async |module: &Wallet, context, _params: ()| -> BitcoinRpcConfig {
                    check_auth(context)?;
                    let config = module.btc_rpc.get_bitcoin_rpc_config();

                    // we need to remove auth, otherwise we'll send over the wire
                    let without_auth = config.url.clone().without_auth().map_err(|_| {
                        ApiError::server_error("Unable to remove auth from bitcoin config URL".to_string())
                    })?;

                    Ok(BitcoinRpcConfig {
                        url: without_auth,
                        ..config
                    })
                }
            },
            api_endpoint! {
                WALLET_SUMMARY_ENDPOINT,
                ApiVersion::new(0, 1),
                async |module: &Wallet, context, _params: ()| -> WalletSummary {
                    Ok(module.get_wallet_summary(&mut context.dbtx().into_nc()).await)
                }
            },
        ]
    }
}

fn calculate_pegin_metrics(
    dbtx: &mut DatabaseTransaction<'_>,
    amount: fedimint_core::Amount,
    fee: fedimint_core::Amount,
) {
    dbtx.on_commit(move || {
        WALLET_INOUT_SATS
            .with_label_values(&["incoming"])
            .observe(amount.sats_f64());
        WALLET_INOUT_FEES_SATS
            .with_label_values(&["incoming"])
            .observe(fee.sats_f64());
        WALLET_PEGIN_SATS.observe(amount.sats_f64());
        WALLET_PEGIN_FEES_SATS.observe(fee.sats_f64());
    });
}

fn calculate_pegout_metrics(
    dbtx: &mut DatabaseTransaction<'_>,
    amount: fedimint_core::Amount,
    fee: fedimint_core::Amount,
) {
    dbtx.on_commit(move || {
        WALLET_INOUT_SATS
            .with_label_values(&["outgoing"])
            .observe(amount.sats_f64());
        WALLET_INOUT_FEES_SATS
            .with_label_values(&["outgoing"])
            .observe(fee.sats_f64());
        WALLET_PEGOUT_SATS.observe(amount.sats_f64());
        WALLET_PEGOUT_FEES_SATS.observe(fee.sats_f64());
    });
}

#[derive(Debug)]
pub struct Wallet {
    cfg: WalletConfig,
    secp: Secp256k1<All>,
    btc_rpc: DynBitcoindRpc,
    our_peer_id: PeerId,
    /// Block count updated periodically by a background task
    block_count_rx: watch::Receiver<Option<u32>>,
    /// Fee rate updated periodically by a background task
    fee_rate_rx: watch::Receiver<Feerate>,
    task_group: TaskGroup,
}

impl Wallet {
    pub async fn new(
        cfg: WalletConfig,
        db: &Database,
        task_group: &TaskGroup,
        our_peer_id: PeerId,
    ) -> anyhow::Result<Wallet> {
        let btc_rpc = create_bitcoind(&cfg.local.bitcoin_rpc)?;
        Ok(Self::new_with_bitcoind(cfg, db, btc_rpc, task_group, our_peer_id).await?)
    }

    pub async fn new_with_bitcoind(
        cfg: WalletConfig,
        db: &Database,
        bitcoind: DynBitcoindRpc,
        task_group: &TaskGroup,
        our_peer_id: PeerId,
    ) -> Result<Wallet, WalletCreationError> {
        Self::spawn_broadcast_pending_task(task_group, &bitcoind, db);

        let (block_count_rx, fee_rate_rx) =
            Self::spawn_bitcoin_update_task(&cfg, task_group, &bitcoind)
                .map_err(|e| WalletCreationError::FeerateSourceError(e.to_string()))?;

        let bitcoind_rpc = bitcoind;

        let bitcoind_net = NetworkLegacyEncodingWrapper(
            bitcoind_rpc
                .get_network()
                .await
                .map_err(|e| WalletCreationError::RpcError(e.to_string()))?,
        );
        if bitcoind_net != cfg.consensus.network {
            return Err(WalletCreationError::WrongNetwork(
                cfg.consensus.network,
                bitcoind_net,
            ));
        }

        let wallet = Wallet {
            cfg,
            secp: Default::default(),
            btc_rpc: bitcoind_rpc,
            our_peer_id,
            block_count_rx,
            fee_rate_rx,
            task_group: task_group.clone(),
        };

        Ok(wallet)
    }

    /// Try to attach signatures to a pending peg-out tx.
    fn sign_peg_out_psbt(
        &self,
        psbt: &mut Psbt,
        peer: PeerId,
        signature: &PegOutSignatureItem,
    ) -> Result<(), ProcessPegOutSigError> {
        let peer_key = self
            .cfg
            .consensus
            .peer_peg_in_keys
            .get(&peer)
            .expect("always called with valid peer id");

        if psbt.inputs.len() != signature.signature.len() {
            return Err(ProcessPegOutSigError::WrongSignatureCount(
                psbt.inputs.len(),
                signature.signature.len(),
            ));
        }

        let mut tx_hasher = SighashCache::new(&psbt.unsigned_tx);
        for (idx, (input, signature)) in psbt
            .inputs
            .iter_mut()
            .zip(signature.signature.iter())
            .enumerate()
        {
            let tx_hash = tx_hasher
                .p2wsh_signature_hash(
                    idx,
                    input
                        .witness_script
                        .as_ref()
                        .expect("Missing witness script"),
                    input.witness_utxo.as_ref().expect("Missing UTXO").value,
                    EcdsaSighashType::All,
                )
                .map_err(|_| ProcessPegOutSigError::SighashError)?;

            let tweak = input
                .proprietary
                .get(&proprietary_tweak_key())
                .expect("we saved it with a tweak");

            let tweaked_peer_key = peer_key.tweak(tweak, &self.secp);
            self.secp
                .verify_ecdsa(
                    &Message::from_digest_slice(&tx_hash[..]).unwrap(),
                    signature,
                    &tweaked_peer_key.key,
                )
                .map_err(|_| ProcessPegOutSigError::InvalidSignature)?;

            if input
                .partial_sigs
                .insert(tweaked_peer_key.into(), EcdsaSig::sighash_all(*signature))
                .is_some()
            {
                // Should never happen since peers only sign a PSBT once
                return Err(ProcessPegOutSigError::DuplicateSignature);
            }
        }
        Ok(())
    }

    fn finalize_peg_out_psbt(
        &self,
        mut unsigned: UnsignedTransaction,
    ) -> Result<PendingTransaction, ProcessPegOutSigError> {
        // We need to save the change output's tweak key to be able to access the funds
        // later on. The tweak is extracted here because the psbt is moved next
        // and not available anymore when the tweak is actually needed in the
        // end to be put into the batch on success.
        let change_tweak: [u8; 33] = unsigned
            .psbt
            .outputs
            .iter()
            .find_map(|output| output.proprietary.get(&proprietary_tweak_key()).cloned())
            .ok_or(ProcessPegOutSigError::MissingOrMalformedChangeTweak)?
            .try_into()
            .map_err(|_| ProcessPegOutSigError::MissingOrMalformedChangeTweak)?;

        if let Err(error) = unsigned.psbt.finalize_mut(&self.secp) {
            return Err(ProcessPegOutSigError::ErrorFinalizingPsbt(error));
        }

        let tx = unsigned.psbt.clone().extract_tx_unchecked_fee_rate();

        Ok(PendingTransaction {
            tx,
            tweak: change_tweak,
            change: unsigned.change,
            destination: unsigned.destination,
            fees: unsigned.fees,
            selected_utxos: unsigned.selected_utxos,
            peg_out_amount: unsigned.peg_out_amount,
            rbf: unsigned.rbf,
        })
    }

    fn get_block_count(&self) -> anyhow::Result<u32> {
        self.block_count_rx
            .borrow()
            .ok_or_else(|| format_err!("Block count not available yet"))
    }

    pub fn get_fee_rate_opt(&self) -> Feerate {
        *self.fee_rate_rx.borrow()
    }

    pub async fn consensus_block_count(&self, dbtx: &mut DatabaseTransaction<'_>) -> u32 {
        let peer_count = self.cfg.consensus.peer_peg_in_keys.to_num_peers().total();

        let mut counts = dbtx
            .find_by_prefix(&BlockCountVotePrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<u32>>()
            .await;

        assert!(counts.len() <= peer_count);

        while counts.len() < peer_count {
            counts.push(0);
        }

        counts.sort_unstable();

        counts[peer_count / 2]
    }

    pub async fn consensus_fee_rate(&self, dbtx: &mut DatabaseTransaction<'_>) -> Feerate {
        let peer_count = self.cfg.consensus.peer_peg_in_keys.to_num_peers().total();

        let mut rates = dbtx
            .find_by_prefix(&FeeRateVotePrefix)
            .await
            .map(|(.., rate)| rate)
            .collect::<Vec<_>>()
            .await;

        assert!(rates.len() <= peer_count);

        while rates.len() < peer_count {
            rates.push(self.cfg.consensus.default_fee);
        }

        rates.sort_unstable();

        rates[peer_count / 2]
    }

    async fn consensus_module_consensus_version(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> ModuleConsensusVersion {
        let num_peers = self.cfg.consensus.peer_peg_in_keys.to_num_peers();

        let mut versions = dbtx
            .find_by_prefix(&ConsensusVersionVotePrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<ModuleConsensusVersion>>()
            .await;

        while versions.len() < num_peers.total() {
            versions.push(ModuleConsensusVersion::new(2, 0));
        }

        assert_eq!(versions.len(), num_peers.total());

        versions.sort_unstable();

        assert!(versions.first() <= versions.last());

        versions[num_peers.max_evil()]
    }

    pub async fn consensus_nonce(&self, dbtx: &mut DatabaseTransaction<'_>) -> [u8; 33] {
        let nonce_idx = dbtx.get_value(&PegOutNonceKey).await.unwrap_or(0);
        dbtx.insert_entry(&PegOutNonceKey, &(nonce_idx + 1)).await;

        nonce_from_idx(nonce_idx)
    }

    async fn sync_up_to_consensus_count<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        old_count: u32,
        new_count: u32,
    ) {
        info!(
            target: LOG_MODULE_WALLET,
            new_count,
            blocks_to_go = new_count - old_count,
            "New consensus count, syncing up",
        );

        // Before we can safely call our bitcoin backend to process the new consensus
        // count, we need to ensure we observed enough confirmations
        self.wait_for_finality_confs_or_shutdown(new_count).await;

        for height in old_count..new_count {
            if height % 100 == 0 {
                debug!(
                    target: LOG_MODULE_WALLET,
                    "Caught up to block {height}"
                );
            }

            // TODO: use batching for mainnet syncing
            trace!(block = height, "Fetching block hash");
            let block_hash =
                retry("get_block_hash", backoff_util::background_backoff(), || {
                    self.btc_rpc.get_block_hash(u64::from(height)) // TODO: use u64 for height everywhere
                })
                .await
                .expect("bitcoind rpc to get block hash");

            if self.consensus_module_consensus_version(dbtx).await
                >= ModuleConsensusVersion::new(2, 2)
            {
                let block = retry("get_block", backoff_util::background_backoff(), || {
                    self.btc_rpc.get_block(&block_hash)
                })
                .await
                .expect("bitcoind rpc to get block");

                for transaction in block.txdata {
                    // We maintain the subset of unspent P2WSH transaction outputs created
                    // since the federation was established in the database.

                    for tx_in in &transaction.input {
                        dbtx.remove_entry(&UnspentTxOutKey(tx_in.previous_output))
                            .await;
                    }

                    for (vout, tx_out) in transaction.output.iter().enumerate() {
                        if if self.cfg.consensus.peer_peg_in_keys.len() > 1 {
                            tx_out.script_pubkey.is_p2wsh()
                        } else {
                            tx_out.script_pubkey.is_p2wpkh()
                        } {
                            let outpoint = bitcoin::OutPoint {
                                txid: transaction.compute_txid(),
                                vout: vout as u32,
                            };

                            dbtx.insert_new_entry(&UnspentTxOutKey(outpoint), tx_out)
                                .await;
                        }
                    }
                }
            }

            let pending_transactions = dbtx
                .find_by_prefix(&PendingTransactionPrefixKey)
                .await
                .map(|(key, transaction)| (key.0, transaction))
                .collect::<HashMap<Txid, PendingTransaction>>()
                .await;
            let pending_transactions_len = pending_transactions.len();

            debug!(
                target: LOG_MODULE_WALLET,
                ?height,
                ?pending_transactions_len,
                "Recognizing change UTXOs"
            );
            for (txid, tx) in &pending_transactions {
                let is_tx_in_block =
                    retry("is_tx_in_block", backoff_util::background_backoff(), || {
                        self.btc_rpc
                            .is_tx_in_block(txid, &block_hash, u64::from(height))
                    })
                    .await
                    .unwrap_or_else(|_| {
                        panic!("Failed checking if tx is in block height {height}")
                    });

                if is_tx_in_block {
                    debug!(
                        target: LOG_MODULE_WALLET,
                        ?txid, ?height, ?block_hash, "Recognizing change UTXO"
                    );
                    self.recognize_change_utxo(dbtx, tx).await;
                } else {
                    debug!(
                        target: LOG_MODULE_WALLET,
                        ?txid,
                        ?height,
                        ?block_hash,
                        "Pending transaction not yet confirmed in this block"
                    );
                }
            }

            dbtx.insert_new_entry(&BlockHashKey(block_hash), &()).await;
        }
    }

    /// Add a change UTXO to our spendable UTXO database after it was included
    /// in a block that we got consensus on.
    async fn recognize_change_utxo<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        pending_tx: &PendingTransaction,
    ) {
        self.remove_rbf_transactions(dbtx, pending_tx).await;

        let script_pk = self
            .cfg
            .consensus
            .peg_in_descriptor
            .tweak(&pending_tx.tweak, &self.secp)
            .script_pubkey();
        for (idx, output) in pending_tx.tx.output.iter().enumerate() {
            if output.script_pubkey == script_pk {
                dbtx.insert_entry(
                    &UTXOKey(bitcoin::OutPoint {
                        txid: pending_tx.tx.compute_txid(),
                        vout: idx as u32,
                    }),
                    &SpendableUTXO {
                        tweak: pending_tx.tweak,
                        amount: output.value,
                    },
                )
                .await;
            }
        }
    }

    /// Removes the `PendingTransaction` and any transactions tied to it via RBF
    async fn remove_rbf_transactions<'a>(
        &self,
        dbtx: &mut DatabaseTransaction<'a>,
        pending_tx: &PendingTransaction,
    ) {
        let mut all_transactions: BTreeMap<Txid, PendingTransaction> = dbtx
            .find_by_prefix(&PendingTransactionPrefixKey)
            .await
            .map(|(key, val)| (key.0, val))
            .collect::<BTreeMap<Txid, PendingTransaction>>()
            .await;

        // We need to search and remove all `PendingTransactions` invalidated by RBF
        let mut pending_to_remove = vec![pending_tx.clone()];
        while let Some(removed) = pending_to_remove.pop() {
            all_transactions.remove(&removed.tx.compute_txid());
            dbtx.remove_entry(&PendingTransactionKey(removed.tx.compute_txid()))
                .await;

            // Search for tx that this `removed` has as RBF
            if let Some(rbf) = &removed.rbf {
                if let Some(tx) = all_transactions.get(&rbf.txid) {
                    pending_to_remove.push(tx.clone());
                }
            }

            // Search for tx that wanted to RBF the `removed` one
            for tx in all_transactions.values() {
                if let Some(rbf) = &tx.rbf {
                    if rbf.txid == removed.tx.compute_txid() {
                        pending_to_remove.push(tx.clone());
                    }
                }
            }
        }
    }

    async fn block_is_known(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        block_hash: BlockHash,
    ) -> bool {
        dbtx.get_value(&BlockHashKey(block_hash)).await.is_some()
    }

    async fn create_peg_out_tx(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        output: &WalletOutputV0,
        change_tweak: &[u8; 33],
    ) -> Result<UnsignedTransaction, WalletOutputError> {
        match output {
            WalletOutputV0::PegOut(peg_out) => self.offline_wallet().create_tx(
                peg_out.amount,
                peg_out.recipient.clone().assume_checked().script_pubkey(),
                vec![],
                self.available_utxos(dbtx).await,
                peg_out.fees.fee_rate,
                change_tweak,
                None,
            ),
            WalletOutputV0::Rbf(rbf) => {
                let tx = dbtx
                    .get_value(&PendingTransactionKey(rbf.txid))
                    .await
                    .ok_or(WalletOutputError::RbfTransactionIdNotFound)?;

                self.offline_wallet().create_tx(
                    tx.peg_out_amount,
                    tx.destination,
                    tx.selected_utxos,
                    self.available_utxos(dbtx).await,
                    tx.fees.fee_rate,
                    change_tweak,
                    Some(rbf.clone()),
                )
            }
        }
    }

    async fn available_utxos(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<(UTXOKey, SpendableUTXO)> {
        dbtx.find_by_prefix(&UTXOPrefixKey)
            .await
            .collect::<Vec<(UTXOKey, SpendableUTXO)>>()
            .await
    }

    pub async fn get_wallet_value(&self, dbtx: &mut DatabaseTransaction<'_>) -> bitcoin::Amount {
        let sat_sum = self
            .available_utxos(dbtx)
            .await
            .into_iter()
            .map(|(_, utxo)| utxo.amount.to_sat())
            .sum();
        bitcoin::Amount::from_sat(sat_sum)
    }

    async fn get_wallet_summary(&self, dbtx: &mut DatabaseTransaction<'_>) -> WalletSummary {
        fn partition_peg_out_and_change(
            transactions: Vec<Transaction>,
        ) -> (Vec<TxOutputSummary>, Vec<TxOutputSummary>) {
            let mut peg_out_txos: Vec<TxOutputSummary> = Vec::new();
            let mut change_utxos: Vec<TxOutputSummary> = Vec::new();

            for tx in transactions {
                let txid = tx.compute_txid();

                // to identify outputs for the peg_out (idx = 0) and change (idx = 1), we lean
                // on how the wallet constructs the transaction
                let peg_out_output = tx
                    .output
                    .first()
                    .expect("tx must contain withdrawal output");

                let change_output = tx.output.last().expect("tx must contain change output");

                peg_out_txos.push(TxOutputSummary {
                    outpoint: bitcoin::OutPoint { txid, vout: 0 },
                    amount: peg_out_output.value,
                });

                change_utxos.push(TxOutputSummary {
                    outpoint: bitcoin::OutPoint { txid, vout: 1 },
                    amount: change_output.value,
                });
            }

            (peg_out_txos, change_utxos)
        }

        let spendable_utxos = self
            .available_utxos(dbtx)
            .await
            .iter()
            .map(|(utxo_key, spendable_utxo)| TxOutputSummary {
                outpoint: utxo_key.0,
                amount: spendable_utxo.amount,
            })
            .collect::<Vec<_>>();

        // constructed peg-outs without threshold signatures
        let unsigned_transactions = dbtx
            .find_by_prefix(&UnsignedTransactionPrefixKey)
            .await
            .map(|(_tx_key, tx)| tx.psbt.unsigned_tx)
            .collect::<Vec<_>>()
            .await;

        // peg-outs with threshold signatures, awaiting finality delay confirmations
        let unconfirmed_transactions = dbtx
            .find_by_prefix(&PendingTransactionPrefixKey)
            .await
            .map(|(_tx_key, tx)| tx.tx)
            .collect::<Vec<_>>()
            .await;

        let (unsigned_peg_out_txos, unsigned_change_utxos) =
            partition_peg_out_and_change(unsigned_transactions);

        let (unconfirmed_peg_out_txos, unconfirmed_change_utxos) =
            partition_peg_out_and_change(unconfirmed_transactions);

        WalletSummary {
            spendable_utxos,
            unsigned_peg_out_txos,
            unsigned_change_utxos,
            unconfirmed_peg_out_txos,
            unconfirmed_change_utxos,
        }
    }

    fn offline_wallet(&self) -> StatelessWallet {
        StatelessWallet {
            descriptor: &self.cfg.consensus.peg_in_descriptor,
            secret_key: &self.cfg.private.peg_in_key,
            secp: &self.secp,
        }
    }

    fn spawn_broadcast_pending_task(
        task_group: &TaskGroup,
        bitcoind: &DynBitcoindRpc,
        db: &Database,
    ) {
        task_group.spawn("broadcast pending", {
            let bitcoind = bitcoind.clone();
            let db = db.clone();
            |handle| async move {
                run_broadcast_pending_tx(db, bitcoind, &handle).await;
            }
        });
    }

    fn spawn_bitcoin_update_task(
        cfg: &WalletConfig,
        task_group: &TaskGroup,
        bitcoind: &DynBitcoindRpc,
    ) -> anyhow::Result<(watch::Receiver<Option<u32>>, watch::Receiver<Feerate>)> {
        let (block_count_tx, block_count_rx) = watch::channel(None);
        let (fee_rate_tx, fee_rate_rx) = watch::channel(cfg.consensus.default_fee);

        let sources = std::env::var(FM_WALLET_FEERATE_SOURCES_ENV)
            .unwrap_or_else(|_| match cfg.consensus.network.0 {
                Network::Bitcoin => "https://mempool.space/api/v1/fees/recommended#.;https://blockstream.info/api/fee-estimates#.\"1\"".to_owned(),
                _ => String::new(),
            })
            .split(';')
            .filter(|s| !s.is_empty())
            .map(|s| Ok(Box::new(FetchJson::from_str(s)?) as Box<dyn FeeRateSource>))
            .chain(iter::once(Ok(
                Box::new(bitcoind.clone()) as Box<dyn FeeRateSource>
            )))
            .collect::<anyhow::Result<Vec<Box<dyn FeeRateSource>>>>()?;
        let feerates = Arc::new(std::sync::Mutex::new(vec![None; sources.len()]));

        let mut desired_interval = tokio::time::interval(if is_running_in_test_env() {
            // In devimint, the setup is blocked by detecting block height changes,
            // and polling more often is not an issue.
            debug!(target: LOG_MODULE_WALLET, "Running in devimint, using fast node polling");
            Duration::from_millis(100)
        } else {
            Duration::from_secs(30)
        });

        task_group.spawn_cancellable("wallet module: background update", {
            let bitcoind = bitcoind.clone();
            async move {
                debug!(target: LOG_MODULE_WALLET, "Updating bitcoin block count");

                let update_block_count = || async {
                    let res = bitcoind
                        .get_block_count()
                        .await
                        .and_then(|count| Ok(u32::try_from(count)?));

                    match res {
                        Ok(c) => {
                            let _ = block_count_tx.send(Some(c));
                        },
                        Err(err) => {
                            warn!(target: LOG_MODULE_WALLET, %err, "Unable to get block count from the node");
                        }
                    }
                };

                let update_fee_rate = || async {
                    trace!(target: LOG_MODULE_WALLET, "Updating bitcoin fee rate");

                    let feerates_new = futures::future::join_all(sources.iter().map(|s| async { (s.name(), s.fetch().await) } )).await;

                    let mut feerates = feerates.lock().expect("lock poisoned");
                    for (i, (name, res)) in feerates_new.into_iter().enumerate() {
                        match res {
                            Ok(ok) => feerates[i] = Some(ok),
                            Err(err) => {
                                warn!(target: LOG_MODULE_WALLET, %err, %name, "Error getting feerate from source");
                            },
                        }
                    }

                    let mut available_feerates : Vec<_> = feerates.iter().filter_map(Clone::clone).map(|r| r.sats_per_kvb).collect();

                    available_feerates.sort_unstable();

                    if let Some(r) = get_median(&available_feerates) {
                        let feerate_with_multiplier = Feerate { sats_per_kvb: r * FEERATE_MULTIPLIER };
                        let _ = fee_rate_tx.send(feerate_with_multiplier);
                    } else {
                        // Regtest node never returns fee rate, so no point spamming about it
                        if !is_running_in_test_env() {
                            warn!(target: LOG_MODULE_WALLET, "Bitcoin node did not return a fee rate");
                        }
                    }
                };

                loop {
                    let start = now();
                    update_block_count().await;
                    update_fee_rate().await;
                    let duration = now().duration_since(start).unwrap_or_default();
                    if Duration::from_secs(10) < duration {
                        warn!(target: LOG_MODULE_WALLET, duration_secs=duration.as_secs(), "Updating from bitcoind slow");
                    }
                    desired_interval.tick().await;
                }
            }
        });
        Ok((block_count_rx, fee_rate_rx))
    }

    /// Shutdown the task group shared throughout fedimintd, giving 60 seconds
    /// for other services to gracefully shutdown.
    async fn graceful_shutdown(&self) {
        if let Err(e) = self
            .task_group
            .clone()
            .shutdown_join_all(Some(Duration::from_secs(60)))
            .await
        {
            panic!("Error while shutting down fedimintd task group: {e}");
        }
    }

    /// Returns once our bitcoin backend observes finality delay confirmations
    /// of the consensus block count. If we don't observe enough confirmations
    /// after one hour, we gracefully shutdown fedimintd. This is necessary
    /// since we can no longer participate in consensus if our bitcoin backend
    /// is unable to observe the same chain tip as our peers.
    async fn wait_for_finality_confs_or_shutdown(&self, consensus_block_count: u32) {
        let backoff = if is_running_in_test_env() {
            // every 100ms for 60s
            backoff_util::custom_backoff(
                Duration::from_millis(100),
                Duration::from_millis(100),
                Some(10 * 60),
            )
        } else {
            // every max 10s for 1 hour
            backoff_util::fibonacci_max_one_hour()
        };

        let wait_for_finality_confs = || async {
            let our_chain_tip_block_count = self.get_block_count()?;
            let consensus_chain_tip_block_count =
                consensus_block_count + self.cfg.consensus.finality_delay;

            if consensus_chain_tip_block_count <= our_chain_tip_block_count {
                Ok(())
            } else {
                Err(anyhow::anyhow!("not enough confirmations"))
            }
        };

        if retry("wait_for_finality_confs", backoff, wait_for_finality_confs)
            .await
            .is_err()
        {
            self.graceful_shutdown().await;
        }
    }
}

#[instrument(level = "debug", skip_all)]
pub async fn run_broadcast_pending_tx(db: Database, rpc: DynBitcoindRpc, tg_handle: &TaskHandle) {
    while !tg_handle.is_shutting_down() {
        broadcast_pending_tx(db.begin_transaction_nc().await, &rpc).await;
        sleep(Duration::from_secs(1)).await;
    }
}

pub async fn broadcast_pending_tx(mut dbtx: DatabaseTransaction<'_>, rpc: &DynBitcoindRpc) {
    let pending_tx: Vec<PendingTransaction> = dbtx
        .find_by_prefix(&PendingTransactionPrefixKey)
        .await
        .map(|(_, val)| val)
        .collect::<Vec<_>>()
        .await;
    let rbf_txids: BTreeSet<Txid> = pending_tx
        .iter()
        .filter_map(|tx| tx.rbf.clone().map(|rbf| rbf.txid))
        .collect();
    debug!(
        target: LOG_MODULE_WALLET,
        "Broadcasting pending transactions (total={}, rbf={})",
        pending_tx.len(),
        rbf_txids.len()
    );

    for PendingTransaction { tx, .. } in pending_tx {
        if !rbf_txids.contains(&tx.compute_txid()) {
            debug!(
                target: LOG_MODULE_WALLET,
                tx = %tx.compute_txid(),
                weight = tx.weight().to_wu(),
                output = ?tx.output,
                "Broadcasting peg-out",
            );
            trace!(transaction = ?tx);
            rpc.submit_transaction(tx).await;
        }
    }
}

struct StatelessWallet<'a> {
    descriptor: &'a Descriptor<CompressedPublicKey>,
    secret_key: &'a secp256k1::SecretKey,
    secp: &'a secp256k1::Secp256k1<secp256k1::All>,
}

impl<'a> StatelessWallet<'a> {
    /// Given a tx created from an `WalletOutput`, validate there will be no
    /// issues submitting the transaction to the Bitcoin network
    fn validate_tx(
        tx: &UnsignedTransaction,
        output: &WalletOutputV0,
        consensus_fee_rate: Feerate,
        network: Network,
    ) -> Result<(), WalletOutputError> {
        if let WalletOutputV0::PegOut(peg_out) = output {
            if !peg_out.recipient.is_valid_for_network(network) {
                return Err(WalletOutputError::WrongNetwork(
                    NetworkLegacyEncodingWrapper(network),
                    NetworkLegacyEncodingWrapper(get_network_for_address(&peg_out.recipient)),
                ));
            }
        }

        // Validate the tx amount is over the dust limit
        if tx.peg_out_amount < tx.destination.minimal_non_dust() {
            return Err(WalletOutputError::PegOutUnderDustLimit);
        }

        // Validate tx fee rate is above the consensus fee rate
        if tx.fees.fee_rate < consensus_fee_rate {
            return Err(WalletOutputError::PegOutFeeBelowConsensus(
                tx.fees.fee_rate,
                consensus_fee_rate,
            ));
        }

        // Validate added fees are above the min relay tx fee
        // BIP-0125 requires 1 sat/vb for RBF by default (same as normal txs)
        let fees = match output {
            WalletOutputV0::PegOut(pegout) => pegout.fees,
            WalletOutputV0::Rbf(rbf) => rbf.fees,
        };
        if fees.fee_rate.sats_per_kvb < u64::from(DEFAULT_MIN_RELAY_TX_FEE) {
            return Err(WalletOutputError::BelowMinRelayFee);
        }

        // Validate fees weight matches the actual weight
        if fees.total_weight != tx.fees.total_weight {
            return Err(WalletOutputError::TxWeightIncorrect(
                fees.total_weight,
                tx.fees.total_weight,
            ));
        }

        Ok(())
    }

    /// Attempts to create a tx ready to be signed from available UTXOs.
    //
    // * `peg_out_amount`: How much the peg-out should be
    // * `destination`: The address the user is pegging-out to
    // * `included_utxos`: UXTOs that must be included (for RBF)
    // * `remaining_utxos`: All other spendable UXTOs
    // * `fee_rate`: How much needs to be spent on fees
    // * `change_tweak`: How the federation can recognize it's change UTXO
    // * `rbf`: If this is an RBF transaction
    #[allow(clippy::too_many_arguments)]
    fn create_tx(
        &self,
        peg_out_amount: bitcoin::Amount,
        destination: ScriptBuf,
        mut included_utxos: Vec<(UTXOKey, SpendableUTXO)>,
        mut remaining_utxos: Vec<(UTXOKey, SpendableUTXO)>,
        mut fee_rate: Feerate,
        change_tweak: &[u8; 33],
        rbf: Option<Rbf>,
    ) -> Result<UnsignedTransaction, WalletOutputError> {
        // Add the rbf fees to the existing tx fees
        if let Some(rbf) = &rbf {
            fee_rate.sats_per_kvb += rbf.fees.fee_rate.sats_per_kvb;
        }

        // When building a transaction we need to take care of two things:
        //  * We need enough input amount to fund all outputs
        //  * We need to keep an eye on the tx weight so we can factor the fees into out
        //    calculation
        // We then go on to calculate the base size of the transaction `total_weight`
        // and the maximum weight per added input which we will add every time
        // we select an input.
        let change_script = self.derive_script(change_tweak);
        let out_weight = (destination.len() * 4 + 1 + 32
            // Add change script weight, it's very likely to be needed if not we just overpay in fees
            + 1 // script len varint, 1 byte for all addresses we accept
            + change_script.len() * 4 // script len
            + 32) as u64; // value
        let mut total_weight = 16 + // version
            12 + // up to 2**16-1 inputs
            12 + // up to 2**16-1 outputs
            out_weight + // weight of all outputs
            16; // lock time
                // https://github.com/fedimint/fedimint/issues/4590
        #[allow(deprecated)]
        let max_input_weight = (self
            .descriptor
            .max_satisfaction_weight()
            .expect("is satisfyable") +
            128 + // TxOutHash
            16 + // TxOutIndex
            16) as u64; // sequence

        // Ensure deterministic ordering of UTXOs for all peers
        included_utxos.sort_by_key(|(_, utxo)| utxo.amount);
        remaining_utxos.sort_by_key(|(_, utxo)| utxo.amount);
        included_utxos.extend(remaining_utxos);

        // Finally we initialize our accumulator for selected input amounts
        let mut total_selected_value = bitcoin::Amount::from_sat(0);
        let mut selected_utxos: Vec<(UTXOKey, SpendableUTXO)> = vec![];
        let mut fees = fee_rate.calculate_fee(total_weight);

        while total_selected_value < peg_out_amount + change_script.minimal_non_dust() + fees {
            match included_utxos.pop() {
                Some((utxo_key, utxo)) => {
                    total_selected_value += utxo.amount;
                    total_weight += max_input_weight;
                    fees = fee_rate.calculate_fee(total_weight);
                    selected_utxos.push((utxo_key, utxo));
                }
                _ => return Err(WalletOutputError::NotEnoughSpendableUTXO), // Not enough UTXOs
            }
        }

        // We always pay ourselves change back to ensure that we don't lose anything due
        // to dust
        let change = total_selected_value - fees - peg_out_amount;
        let output: Vec<TxOut> = vec![
            TxOut {
                value: peg_out_amount,
                script_pubkey: destination.clone(),
            },
            TxOut {
                value: change,
                script_pubkey: change_script,
            },
        ];
        let mut change_out = bitcoin::psbt::Output::default();
        change_out
            .proprietary
            .insert(proprietary_tweak_key(), change_tweak.to_vec());

        info!(
            target: LOG_MODULE_WALLET,
            inputs = selected_utxos.len(),
            input_sats = total_selected_value.to_sat(),
            peg_out_sats = peg_out_amount.to_sat(),
            ?total_weight,
            fees_sats = fees.to_sat(),
            fee_rate = fee_rate.sats_per_kvb,
            change_sats = change.to_sat(),
            "Creating peg-out tx",
        );

        let transaction = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: LockTime::ZERO,
            input: selected_utxos
                .iter()
                .map(|(utxo_key, _utxo)| TxIn {
                    previous_output: utxo_key.0,
                    script_sig: Default::default(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: bitcoin::Witness::new(),
                })
                .collect(),
            output,
        };
        info!(
            target: LOG_MODULE_WALLET,
            txid = %transaction.compute_txid(), "Creating peg-out tx"
        );

        // FIXME: use custom data structure that guarantees more invariants and only
        // convert to PSBT for finalization
        let psbt = Psbt {
            unsigned_tx: transaction,
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: selected_utxos
                .iter()
                .map(|(_utxo_key, utxo)| {
                    let script_pubkey = self
                        .descriptor
                        .tweak(&utxo.tweak, self.secp)
                        .script_pubkey();
                    Input {
                        non_witness_utxo: None,
                        witness_utxo: Some(TxOut {
                            value: utxo.amount,
                            script_pubkey,
                        }),
                        partial_sigs: Default::default(),
                        sighash_type: None,
                        redeem_script: None,
                        witness_script: Some(
                            self.descriptor
                                .tweak(&utxo.tweak, self.secp)
                                .script_code()
                                .expect("Failed to tweak descriptor"),
                        ),
                        bip32_derivation: Default::default(),
                        final_script_sig: None,
                        final_script_witness: None,
                        ripemd160_preimages: Default::default(),
                        sha256_preimages: Default::default(),
                        hash160_preimages: Default::default(),
                        hash256_preimages: Default::default(),
                        proprietary: vec![(proprietary_tweak_key(), utxo.tweak.to_vec())]
                            .into_iter()
                            .collect(),
                        tap_key_sig: Default::default(),
                        tap_script_sigs: Default::default(),
                        tap_scripts: Default::default(),
                        tap_key_origins: Default::default(),
                        tap_internal_key: Default::default(),
                        tap_merkle_root: Default::default(),
                        unknown: Default::default(),
                    }
                })
                .collect(),
            outputs: vec![Default::default(), change_out],
        };

        Ok(UnsignedTransaction {
            psbt,
            signatures: vec![],
            change,
            fees: PegOutFees {
                fee_rate,
                total_weight,
            },
            destination,
            selected_utxos,
            peg_out_amount,
            rbf,
        })
    }

    fn sign_psbt(&self, psbt: &mut Psbt) {
        let mut tx_hasher = SighashCache::new(&psbt.unsigned_tx);

        for (idx, (psbt_input, _tx_input)) in psbt
            .inputs
            .iter_mut()
            .zip(psbt.unsigned_tx.input.iter())
            .enumerate()
        {
            let tweaked_secret = {
                let tweak = psbt_input
                    .proprietary
                    .get(&proprietary_tweak_key())
                    .expect("Malformed PSBT: expected tweak");

                self.secret_key.tweak(tweak, self.secp)
            };

            let tx_hash = tx_hasher
                .p2wsh_signature_hash(
                    idx,
                    psbt_input
                        .witness_script
                        .as_ref()
                        .expect("Missing witness script"),
                    psbt_input
                        .witness_utxo
                        .as_ref()
                        .expect("Missing UTXO")
                        .value,
                    EcdsaSighashType::All,
                )
                .expect("Failed to create segwit sighash");

            let signature = self.secp.sign_ecdsa(
                &Message::from_digest_slice(&tx_hash[..]).unwrap(),
                &tweaked_secret,
            );

            psbt_input.partial_sigs.insert(
                bitcoin::PublicKey {
                    compressed: true,
                    inner: secp256k1::PublicKey::from_secret_key(self.secp, &tweaked_secret),
                },
                EcdsaSig::sighash_all(signature),
            );
        }
    }

    fn derive_script(&self, tweak: &[u8]) -> ScriptBuf {
        struct CompressedPublicKeyTranslator<'t, 's, Ctx: Verification> {
            tweak: &'t [u8],
            secp: &'s Secp256k1<Ctx>,
        }

        impl<'t, 's, Ctx: Verification>
            miniscript::Translator<CompressedPublicKey, CompressedPublicKey, Infallible>
            for CompressedPublicKeyTranslator<'t, 's, Ctx>
        {
            fn pk(&mut self, pk: &CompressedPublicKey) -> Result<CompressedPublicKey, Infallible> {
                let hashed_tweak = {
                    let mut hasher = HmacEngine::<sha256::Hash>::new(&pk.key.serialize()[..]);
                    hasher.input(self.tweak);
                    Hmac::from_engine(hasher).to_byte_array()
                };

                Ok(CompressedPublicKey {
                    key: pk
                        .key
                        .add_exp_tweak(
                            self.secp,
                            &Scalar::from_be_bytes(hashed_tweak).expect("can't fail"),
                        )
                        .expect("tweaking failed"),
                })
            }
            translate_hash_fail!(CompressedPublicKey, CompressedPublicKey, Infallible);
        }

        let descriptor = self
            .descriptor
            .translate_pk(&mut CompressedPublicKeyTranslator {
                tweak,
                secp: self.secp,
            })
            .expect("can't fail");

        descriptor.script_pubkey()
    }
}

pub fn nonce_from_idx(nonce_idx: u64) -> [u8; 33] {
    let mut nonce: [u8; 33] = [0; 33];
    // Make it look like a compressed pubkey, has to be either 0x02 or 0x03
    nonce[0] = 0x02;
    nonce[1..].copy_from_slice(&nonce_idx.consensus_hash::<bitcoin::hashes::sha256::Hash>()[..]);

    nonce
}

/// A peg-out tx that is ready to be broadcast with a tweak for the change UTXO
#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransaction {
    pub tx: bitcoin::Transaction,
    pub tweak: [u8; 33],
    pub change: bitcoin::Amount,
    pub destination: ScriptBuf,
    pub fees: PegOutFees,
    pub selected_utxos: Vec<(UTXOKey, SpendableUTXO)>,
    pub peg_out_amount: bitcoin::Amount,
    pub rbf: Option<Rbf>,
}

impl Serialize for PendingTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.consensus_encode_to_hex())
        } else {
            serializer.serialize_bytes(&self.consensus_encode_to_vec())
        }
    }
}

/// A PSBT that is awaiting enough signatures from the federation to becoming a
/// `PendingTransaction`
#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable)]
pub struct UnsignedTransaction {
    pub psbt: Psbt,
    pub signatures: Vec<(PeerId, PegOutSignatureItem)>,
    pub change: bitcoin::Amount,
    pub fees: PegOutFees,
    pub destination: ScriptBuf,
    pub selected_utxos: Vec<(UTXOKey, SpendableUTXO)>,
    pub peg_out_amount: bitcoin::Amount,
    pub rbf: Option<Rbf>,
}

impl Serialize for UnsignedTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.consensus_encode_to_hex())
        } else {
            serializer.serialize_bytes(&self.consensus_encode_to_vec())
        }
    }
}

fn get_median(vals: &[u64]) -> Option<u64> {
    if vals.is_empty() {
        return None;
    }
    let len = vals.len();
    let mid = len / 2;

    if len % 2 == 0 {
        Some((vals[mid - 1] + vals[mid]) / 2)
    } else {
        Some(vals[mid])
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use bitcoin::hashes::Hash;
    use bitcoin::Network::{Bitcoin, Testnet};
    use bitcoin::{secp256k1, Address, Amount, OutPoint, Txid};
    use fedimint_core::encoding::btc::NetworkLegacyEncodingWrapper;
    use fedimint_core::Feerate;
    use fedimint_wallet_common::{PegOut, PegOutFees, Rbf, WalletOutputV0};
    use miniscript::descriptor::Wsh;

    use crate::common::PegInDescriptor;
    use crate::{
        CompressedPublicKey, OsRng, SpendableUTXO, StatelessWallet, UTXOKey, WalletOutputError,
    };

    #[test]
    fn create_tx_should_validate_amounts() {
        let secp = secp256k1::Secp256k1::new();

        let descriptor = PegInDescriptor::Wsh(
            Wsh::new_sortedmulti(
                3,
                (0..4)
                    .map(|_| secp.generate_keypair(&mut OsRng))
                    .map(|(_, key)| CompressedPublicKey { key })
                    .collect(),
            )
            .unwrap(),
        );

        let (secret_key, _) = secp.generate_keypair(&mut OsRng);

        let wallet = StatelessWallet {
            descriptor: &descriptor,
            secret_key: &secret_key,
            secp: &secp,
        };

        let spendable = SpendableUTXO {
            tweak: [0; 33],
            amount: bitcoin::Amount::from_sat(3000),
        };

        let recipient = Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf").unwrap();

        let fee = Feerate { sats_per_kvb: 1000 };
        let weight = 875;

        // not enough SpendableUTXO
        // tx fee = ceil(875 / 4) * 1 sat/vb = 219
        // change script dust = 330
        // spendable sats = 3000 - 219 - 330 = 2451
        let tx = wallet.create_tx(
            Amount::from_sat(2452),
            recipient.clone().assume_checked().script_pubkey(),
            vec![],
            vec![(UTXOKey(OutPoint::null()), spendable.clone())],
            fee,
            &[0; 33],
            None,
        );
        assert_eq!(tx, Err(WalletOutputError::NotEnoughSpendableUTXO));

        // successful tx creation
        let mut tx = wallet
            .create_tx(
                Amount::from_sat(1000),
                recipient.clone().assume_checked().script_pubkey(),
                vec![],
                vec![(UTXOKey(OutPoint::null()), spendable)],
                fee,
                &[0; 33],
                None,
            )
            .expect("is ok");

        // peg out weight is incorrectly set to 0
        let res = StatelessWallet::validate_tx(&tx, &rbf(fee.sats_per_kvb, 0), fee, Bitcoin);
        assert_eq!(res, Err(WalletOutputError::TxWeightIncorrect(0, weight)));

        // fee rate set below min relay fee to 0
        let res = StatelessWallet::validate_tx(&tx, &rbf(0, weight), fee, Bitcoin);
        assert_eq!(res, Err(WalletOutputError::BelowMinRelayFee));

        // fees are okay
        let res = StatelessWallet::validate_tx(&tx, &rbf(fee.sats_per_kvb, weight), fee, Bitcoin);
        assert_eq!(res, Ok(()));

        // tx has fee below consensus
        tx.fees = PegOutFees::new(0, weight);
        let res = StatelessWallet::validate_tx(&tx, &rbf(fee.sats_per_kvb, weight), fee, Bitcoin);
        assert_eq!(
            res,
            Err(WalletOutputError::PegOutFeeBelowConsensus(
                Feerate { sats_per_kvb: 0 },
                fee
            ))
        );

        // tx has peg-out amount under dust limit
        tx.peg_out_amount = bitcoin::Amount::ZERO;
        let res = StatelessWallet::validate_tx(&tx, &rbf(fee.sats_per_kvb, weight), fee, Bitcoin);
        assert_eq!(res, Err(WalletOutputError::PegOutUnderDustLimit));

        // tx is invalid for network
        let output = WalletOutputV0::PegOut(PegOut {
            recipient,
            amount: bitcoin::Amount::from_sat(1000),
            fees: PegOutFees::new(100, weight),
        });
        let res = StatelessWallet::validate_tx(&tx, &output, fee, Testnet);
        assert_eq!(
            res,
            Err(WalletOutputError::WrongNetwork(
                NetworkLegacyEncodingWrapper(Testnet),
                NetworkLegacyEncodingWrapper(Bitcoin)
            ))
        );
    }

    fn rbf(sats_per_kvb: u64, total_weight: u64) -> WalletOutputV0 {
        WalletOutputV0::Rbf(Rbf {
            fees: PegOutFees::new(sats_per_kvb, total_weight),
            txid: Txid::all_zeros(),
        })
    }
}

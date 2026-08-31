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
mod metrics;

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
    OutputInfo, WalletCommonInit, WalletConsensusItem, WalletInput, WalletModuleTypes,
    WalletOutput, WalletOutputOutcome,
};
use db::{
    DbKeyPrefix, FederationWalletKey, FederationWalletPrefix, Output, OutputKey, OutputPrefix,
    SignaturesKey, SignaturesPrefix, SignaturesTxidPrefix, SpentOutputKey, SpentOutputPrefix,
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
use fedimint_core::envs::{
    FM_ENABLE_MODULE_WALLETV2_ENV, is_env_var_set_opt, is_running_in_test_env,
};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiVersion, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, MultiApiVersion, TransactionItemAmounts, public_api_endpoint,
};
#[cfg(not(target_family = "wasm"))]
use fedimint_core::task::TaskGroup;
use fedimint_core::task::sleep;
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_core::{
    InPoint, NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send, push_db_pair_items, util,
};
use fedimint_logging::LOG_MODULE_WALLETV2;
use fedimint_server_core::bitcoin_rpc::ServerBitcoinRpcMonitor;
use fedimint_server_core::config::{PeerHandleOps, PeerHandleOpsExt};
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, EnvVarDoc, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
pub use fedimint_walletv2_common as common;
/// Re-exported for existing callers; the constant lives in the common crate so
/// that the client can render peg-in confirmation progress against it.
pub use fedimint_walletv2_common::CONFIRMATION_FINALITY_DELAY;
use fedimint_walletv2_common::config::{
    FeeConsensus, WalletClientConfig, WalletConfig, WalletConfigPrivate,
};
use fedimint_walletv2_common::endpoint_constants::{
    CONSENSUS_BLOCK_COUNT_ENDPOINT, CONSENSUS_FEERATE_ENDPOINT, FEDERATION_WALLET_ENDPOINT,
    OUTPUT_INFO_SLICE_ENDPOINT, PENDING_OUTPUTS_ENDPOINT, PENDING_TRANSACTION_CHAIN_ENDPOINT,
    RECEIVE_FEE_ENDPOINT, SEND_FEE_ENDPOINT, TRANSACTION_CHAIN_ENDPOINT, TRANSACTION_ID_ENDPOINT,
};
use fedimint_walletv2_common::{
    FederationWallet, MODULE_CONSENSUS_VERSION, PendingOutput, PendingOutputs, TxInfo,
    WalletInputError, WalletOutputError, descriptor, is_potential_receive, tweak_public_key,
};
use futures::StreamExt;
use miniscript::descriptor::Wsh;
use rand::rngs::OsRng;
use secp256k1::ecdsa::Signature;
use secp256k1::{PublicKey, Scalar, SecretKey};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tokio::sync::watch;
use tracing::{debug, info};

use crate::db::{
    BlockCountVoteKey, BlockCountVotePrefix, FeeRateVoteKey, FeeRateVotePrefix, TxInfoKey,
    TxInfoPrefix, UnconfirmedTxKey, UnconfirmedTxPrefix, UnsignedTxKey, UnsignedTxPrefix,
};
use crate::metrics::{
    WALLET_BLOCK_COUNT, WALLET_INOUT_FEES_SATS, WALLET_INOUT_SATS, WALLET_PEGIN_FEES_SATS,
    WALLET_PEGIN_SATS, WALLET_PEGOUT_FEES_SATS, WALLET_PEGOUT_SATS,
};

/// Maximum number of blocks the consensus block count can advance in a single
/// consensus item to limit the work done in one `process_consensus_item` step.
const MAX_BLOCK_COUNT_INCREMENT: u64 = 5;

/// Devimint tests can mine many regtest blocks at once, so use a larger cap in
/// test environments to avoid waiting on several consensus sessions.
const TEST_MAX_BLOCK_COUNT_INCREMENT: u64 = 100;

/// Minimum fee rate vote of 1 sat/vB to ensure we never propose a fee rate
/// below what Bitcoin Core will relay.
const MIN_FEERATE_VOTE_SATS_PER_KVB: u64 = 1000;

/// Number of blocks below the local chain tip that the pending receive scanner
/// reports on.
///
/// Only the first [`CONFIRMATION_FINALITY_DELAY`] blocks of this window are
/// strictly necessary, since deeper outputs are already in the consensus output
/// log. The window deliberately extends past that so a peg-in keeps being
/// reported for a while after it becomes final: a client needs a moment to
/// notice the consensus entry and start its claim, and without the overlap its
/// progress display would briefly fall back to reporting nothing at all.
const MAX_PENDING_DEPTH: u64 = 2 * CONFIRMATION_FINALITY_DELAY;

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

/// Filtered receive outputs of the blocks in the pending window, keyed by
/// height and tagged with the hash they were derived from.
type BlockCache = BTreeMap<u64, (bitcoin::BlockHash, Vec<PendingOutput>)>;

/// Filtered receive outputs of the transactions currently in the mempool.
///
/// Every transaction is kept, including those with no matching outputs, so that
/// a scan only fetches transactions it has never seen. On a busy mainnet node
/// this holds on the order of tens of thousands of empty entries, which is a
/// few megabytes and far cheaper than refetching the mempool each scan.
type MempoolCache = BTreeMap<Txid, Vec<PendingOutput>>;

/// State the pending receive scanner carries between runs.
#[derive(Default)]
struct PendingCache {
    blocks: BlockCache,
    mempool: MempoolCache,
}

/// Returns the receive outputs of `tx` that pass the probabilistic filter.
fn filtered_receive_outputs(
    tx: &Transaction,
    pks_hash: &sha256::Hash,
    height: Option<u64>,
) -> Vec<PendingOutput> {
    let txid = tx.compute_txid();

    tx.output
        .iter()
        .enumerate()
        .filter(|(_, tx_out)| is_potential_receive(&tx_out.script_pubkey, pks_hash))
        .map(|(vout, tx_out)| PendingOutput {
            script: tx_out.script_pubkey.clone(),
            outpoint: bitcoin::OutPoint {
                txid,
                vout: u32::try_from(vout)
                    .expect("Bitcoin transaction has more than u32::MAX outputs"),
            },
            value: tx_out.value,
            height,
        })
        .collect()
}

/// Collects the receive outputs of the most recently mined blocks.
///
/// Scans the last [`MAX_PENDING_DEPTH`] blocks below the guardian's local chain
/// tip. The window is relative to the tip rather than to the consensus block
/// count, so the work stays bounded even if the federation's consensus block
/// count is lagging badly, and so a peg-in keeps being reported for a while
/// after it becomes final.
///
/// Blocks are only fetched when the hash at a height is absent from `cache` or
/// differs from the cached one, which keeps the steady state cost at one block
/// fetch per new block and makes reorgs within the window self-repairing.
async fn scan_pending_blocks(
    btc_rpc: &ServerBitcoinRpcMonitor,
    pks_hash: &sha256::Hash,
    block_count: u64,
    cache: &mut BlockCache,
) -> anyhow::Result<()> {
    let start = block_count.saturating_sub(MAX_PENDING_DEPTH);

    // Drop the blocks that have fallen out of the window as the chain advanced.
    cache.retain(|height, _| (start..block_count).contains(height));

    for height in start..block_count {
        let block_hash = btc_rpc.get_block_hash(height).await?;

        if cache
            .get(&height)
            .is_some_and(|(cached_hash, _)| *cached_hash == block_hash)
        {
            continue;
        }

        let block = btc_rpc.get_block(&block_hash).await?;

        let outputs = block
            .txdata
            .iter()
            .flat_map(|tx| filtered_receive_outputs(tx, pks_hash, Some(height)))
            .collect::<Vec<PendingOutput>>();

        cache.insert(height, (block_hash, outputs));
    }

    Ok(())
}

/// Collects the receive outputs of the transactions in the node's mempool.
///
/// Returns whether the backend has mempool visibility at all. Esplora cannot
/// enumerate a mempool, so its guardians report `false` and simply never
/// surface unmined peg-ins.
///
/// Only transactions absent from `cache` are fetched, and entries that have
/// left the mempool are dropped, so eviction and replacement are handled by
/// rebuilding the retained set rather than by tracking them explicitly. A
/// transaction that disappears between being listed and being fetched is
/// skipped rather than treated as an error, since that is the ordinary outcome
/// of it being mined mid-scan.
async fn scan_pending_mempool(
    btc_rpc: &ServerBitcoinRpcMonitor,
    pks_hash: &sha256::Hash,
    cache: &mut MempoolCache,
) -> anyhow::Result<bool> {
    let Some(txids) = btc_rpc.get_mempool_txids().await? else {
        cache.clear();

        return Ok(false);
    };

    let txids: BTreeSet<Txid> = txids.into_iter().collect();

    cache.retain(|txid, _| txids.contains(txid));

    for txid in txids {
        if cache.contains_key(&txid) {
            continue;
        }

        if let Some(tx) = btc_rpc.get_mempool_tx(&txid).await? {
            cache.insert(txid, filtered_receive_outputs(&tx, pks_hash, None));
        }
    }

    Ok(true)
}

/// Collects every receive output a guardian can see but the federation has not
/// yet recorded, from both the recent blocks and the mempool.
async fn scan_pending_receives(
    btc_rpc: &ServerBitcoinRpcMonitor,
    pks_hash: &sha256::Hash,
    cache: &mut PendingCache,
) -> anyhow::Result<PendingOutputs> {
    let status = btc_rpc
        .status()
        .context("Bitcoin backend is not connected")?;

    scan_pending_blocks(btc_rpc, pks_hash, status.block_count, &mut cache.blocks).await?;

    let mempool_visibility = scan_pending_mempool(btc_rpc, pks_hash, &mut cache.mempool).await?;

    let mined = cache
        .blocks
        .values()
        .flat_map(|(_, outputs)| outputs.iter().cloned());

    // A transaction mined between the two scans appears in both; the mined
    // entry is the stronger signal, so it wins on the client side by way of the
    // per-outpoint merge preferring a known height.
    let outputs = mined
        .chain(cache.mempool.values().flatten().cloned())
        .collect::<Vec<PendingOutput>>();

    debug!(
        target: LOG_MODULE_WALLETV2,
        block_count = status.block_count,
        mempool_visibility,
        mempool_txs_num = cache.mempool.len(),
        pending_outputs_num = outputs.len(),
        "Scanned for pending receives"
    );

    Ok(PendingOutputs {
        block_count: status.block_count,
        outputs,
        mempool_visibility,
    })
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
                DbKeyPrefix::Output => {
                    push_db_pair_items!(
                        dbtx,
                        OutputPrefix,
                        OutputKey,
                        Output,
                        wallet,
                        "Wallet Outputs"
                    );
                }
                DbKeyPrefix::SpentOutput => {
                    push_db_pair_items!(
                        dbtx,
                        SpentOutputPrefix,
                        SpentOutputKey,
                        (),
                        wallet,
                        "Wallet Spent Outputs"
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

    fn is_enabled_by_default(&self) -> bool {
        is_env_var_set_opt(FM_ENABLE_MODULE_WALLETV2_ENV).unwrap_or(true)
    }

    fn get_documented_env_vars(&self) -> Vec<EnvVarDoc> {
        vec![EnvVarDoc {
            name: FM_ENABLE_MODULE_WALLETV2_ENV,
            description: "Set to 0/false to disable the WalletV2 module. Enabled by default.",
        }]
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        // Eagerly register metrics so the series exist before the first transaction
        for direction in ["incoming", "outgoing"] {
            WALLET_INOUT_SATS
                .with_label_values(&[direction])
                .get_sample_count();
            WALLET_INOUT_FEES_SATS
                .with_label_values(&[direction])
                .get_sample_count();
        }
        WALLET_PEGIN_SATS.get_sample_count();
        WALLET_PEGIN_FEES_SATS.get_sample_count();
        WALLET_PEGOUT_SATS.get_sample_count();
        WALLET_PEGOUT_FEES_SATS.get_sample_count();

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
            descriptor: config.descriptor,
            send_tx_vbytes: config.send_tx_vbytes,
            receive_tx_vbytes: config.receive_tx_vbytes,
            feerate_base: config.feerate_base,
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

                self.verify_signatures(
                    &unsigned_tx,
                    &signatures,
                    self.cfg.private.bitcoin_sk.public_key(secp256k1::SECP256K1),
                )
                .expect("Our signatures failed verification against our private key");

                WalletConsensusItem::Signatures(key.0, signatures)
            })
            .collect::<Vec<WalletConsensusItem>>()
            .await;

        if let Some(status) = self.btc_rpc.status() {
            assert_eq!(status.network, self.cfg.consensus.network);

            let block_count_vote = status
                .block_count
                .saturating_sub(CONFIRMATION_FINALITY_DELAY);

            let consensus_block_count = self.consensus_block_count(dbtx).await;

            let max_block_count_increment = if is_running_in_test_env() {
                TEST_MAX_BLOCK_COUNT_INCREMENT
            } else {
                MAX_BLOCK_COUNT_INCREMENT
            };

            let block_count_vote = match consensus_block_count {
                0 => block_count_vote,
                _ => block_count_vote.min(consensus_block_count + max_block_count_increment),
            };

            WALLET_BLOCK_COUNT.set(i64::try_from(block_count_vote).unwrap_or(i64::MAX));

            items.push(WalletConsensusItem::BlockCount(block_count_vote));

            let feerate_vote = status
                .fee_rate
                .sats_per_kvb
                .max(MIN_FEERATE_VOTE_SATS_PER_KVB);

            items.push(WalletConsensusItem::Feerate(Some(feerate_vote)));
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
            .insert_entry(&SpentOutputKey(input.output_index), &())
            .await
            .is_some()
        {
            return Err(WalletInputError::OutputAlreadySpent);
        }

        let Output(tracked_outpoint, tracked_output) = dbtx
            .get_value(&OutputKey(input.output_index))
            .await
            .ok_or(WalletInputError::UnknownOutputIndex)?;

        let tweaked_pubkey = self
            .descriptor(&input.tweak.consensus_hash())
            .script_pubkey();

        if tracked_output.script_pubkey != tweaked_pubkey {
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

        let output_value = tracked_output
            .value
            .checked_sub(input.fee)
            .ok_or(WalletInputError::ArithmeticOverflow)?;

        if let Some(wallet) = dbtx.remove_entry(&FederationWalletKey).await {
            // Assuming the first receive into the federation is made through a
            // standard transaction, its output value is over the P2WSH dust
            // limit. By induction so is this change value.
            let change_value = wallet
                .value
                .checked_add(output_value)
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
                            value: tracked_output.value,
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
                    value: tracked_output.value,
                    outpoint: tracked_outpoint,
                    tweak: input.tweak.consensus_hash(),
                },
            )
            .await;
        }

        let amount = output_value
            .to_sat()
            .checked_mul(1000)
            .map(fedimint_core::Amount::from_msats)
            .ok_or(WalletInputError::ArithmeticOverflow)?;

        let fee = self.cfg.consensus.fee_consensus.fee(amount);

        calculate_pegin_metrics(dbtx, amount, fee);

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(amount),
                fees: Amounts::new_bitcoin(fee),
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

        let fee = self.cfg.consensus.fee_consensus.fee(amount);

        calculate_pegout_metrics(dbtx, amount, fee);

        Ok(TransactionItemAmounts {
            amounts: Amounts::new_bitcoin(amount),
            fees: Amounts::new_bitcoin(fee),
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
            public_api_endpoint! {
                CONSENSUS_BLOCK_COUNT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> u64 {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.consensus_block_count(&mut dbtx).await)
                }
            },
            public_api_endpoint! {
                CONSENSUS_FEERATE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<u64> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.consensus_feerate(&mut dbtx).await)
                }
            },
            public_api_endpoint! {
                FEDERATION_WALLET_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Wallet, context, _params: ()| -> Option<FederationWallet> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(dbtx.get_value(&FederationWalletKey).await)
                }
            },
            public_api_endpoint! {
                SEND_FEE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<Amount> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.send_fee(&mut dbtx).await)
                }
            },
            public_api_endpoint! {
                RECEIVE_FEE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<Amount> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.receive_fee(&mut dbtx).await)
                }
            },
            public_api_endpoint! {
                TRANSACTION_ID_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, params: OutPoint| -> Option<Txid> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.tx_id(&mut dbtx, params).await)
                }
            },
            public_api_endpoint! {
                OUTPUT_INFO_SLICE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, params: (u64, u64)| -> Vec<OutputInfo> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.get_outputs(&mut dbtx, params.0, params.1).await)
                }
            },
            public_api_endpoint! {
                PENDING_TRANSACTION_CHAIN_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Vec<TxInfo> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.pending_tx_chain(&mut dbtx).await)
                }
            },
            public_api_endpoint! {
                TRANSACTION_CHAIN_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Vec<TxInfo> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.tx_chain(&mut dbtx).await)
                }
            },
            public_api_endpoint! {
                PENDING_OUTPUTS_ENDPOINT,
                ApiVersion::new(0, 2),
                async |module: &Wallet, _context, _params: ()| -> PendingOutputs {
                    // Deliberately reads local, non-consensus state rather than
                    // the database. Clients must not request this via threshold
                    // consensus; see the client side api for details.
                    Ok(module.pending_outputs.borrow().clone())
                }
            },
        ]
    }

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion::new(0, 2)])
            .expect("walletv2 declares one API version per major version")
    }
}

#[derive(Debug)]
pub struct Wallet {
    cfg: WalletConfig,
    db: Database,
    btc_rpc: ServerBitcoinRpcMonitor,
    /// Local, non-consensus view of receive outputs that have been mined but
    /// are not yet deep enough to enter the consensus output log.
    ///
    /// Maintained by the `scan_pending_receives` background task and read by
    /// the pending outputs endpoint. This is intentionally in-memory only: it
    /// is per-guardian divergent data that has no business in the consensus
    /// database, and it is cheap to rebuild from a handful of blocks on
    /// restart.
    pending_outputs: watch::Receiver<PendingOutputs>,
}

impl Wallet {
    fn new(
        cfg: WalletConfig,
        db: &Database,
        task_group: &TaskGroup,
        btc_rpc: ServerBitcoinRpcMonitor,
    ) -> Wallet {
        Self::spawn_broadcast_unconfirmed_txs_task(btc_rpc.clone(), db.clone(), task_group);

        let (pending_sender, pending_outputs) = watch::channel(PendingOutputs::default());

        Self::spawn_pending_receive_scanner(
            btc_rpc.clone(),
            cfg.consensus.bitcoin_pks.consensus_hash(),
            pending_sender,
            task_group,
        );

        Wallet {
            cfg,
            btc_rpc,
            db: db.clone(),
            pending_outputs,
        }
    }

    /// Maintains [`Wallet::pending_outputs`] by scanning the blocks just below
    /// the guardian's local chain tip.
    ///
    /// This deliberately runs outside of consensus. Most of this window sits
    /// above the consensus block count precisely because the federation does
    /// not consider those blocks final yet, and each guardian sees a slightly
    /// different tip, so nothing derived here may ever influence consensus
    /// state. It exists only so clients can render peg-in progress rather than
    /// showing nothing for the hour it takes a deposit to become claimable.
    fn spawn_pending_receive_scanner(
        btc_rpc: ServerBitcoinRpcMonitor,
        pks_hash: sha256::Hash,
        sender: watch::Sender<PendingOutputs>,
        task_group: &TaskGroup,
    ) {
        task_group.spawn_cancellable("scan_pending_receives", async move {
            // Carried across scans so that each one only fetches blocks and
            // mempool transactions it has not already seen.
            let mut cache = PendingCache::default();

            // Follow the monitor's own refresh cadence rather than an
            // independent timer, so we never scan a chain tip that is already
            // stale by up to a full update interval.
            let mut status = btc_rpc.subscribe_status();

            loop {
                match scan_pending_receives(&btc_rpc, &pks_hash, &mut cache).await {
                    Ok(pending) => {
                        sender.send_replace(pending);
                    }
                    Err(err) => {
                        // This view is advisory, so a guardian that cannot
                        // reach its bitcoin backend degrades to reporting
                        // nothing pending rather than failing.
                        debug!(
                            target: LOG_MODULE_WALLETV2,
                            err = %err.fmt_compact_anyhow(),
                            "Error scanning for pending receives"
                        );

                        sender.send_replace(PendingOutputs::default());
                    }
                }

                if status.changed().await.is_err() {
                    break;
                }
            }
        });
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
                    if let Err(err) = btc_rpc.submit_transaction(unconfirmed_tx.tx).await {
                        debug!(
                            target: LOG_MODULE_WALLETV2,
                            err = %err.fmt_compact_anyhow(),
                            "Error broadcasting unconfirmed transaction"
                        );
                    }
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

        debug!(
            target: LOG_MODULE_WALLETV2,
            %peer,
            vote = block_count_vote,
            old_consensus = old_consensus_block_count,
            new_consensus = new_consensus_block_count,
            advanced = new_consensus_block_count - old_consensus_block_count,
            "Processed block count vote"
        );

        // Outside regtest, do not sync blocks that predate the federation itself.
        // Regtest starts from scratch, so scan from genesis to avoid races where
        // test deposits are mined before the first walletv2 block count
        // transition is processed.
        let scan_from_genesis = self.cfg.consensus.network == bitcoin::Network::Regtest;
        if old_consensus_block_count == 0 && !scan_from_genesis {
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

            let txs_num = block.txdata.len();
            let mut potential_receives_num: usize = 0;

            for tx in block.txdata {
                dbtx.remove_entry(&UnconfirmedTxKey(tx.compute_txid()))
                    .await;

                // We maintain an append-only log of transaction outputs that pass
                // the probabilistic receive filter created since the federation was
                // established. This is downloaded by clients to detect pegins and
                // claim them by index.

                for (vout, tx_out) in tx.output.iter().enumerate() {
                    if is_potential_receive(&tx_out.script_pubkey, &pks_hash) {
                        let outpoint = bitcoin::OutPoint {
                            txid: tx.compute_txid(),
                            vout: u32::try_from(vout)
                                .expect("Bitcoin transaction has more than u32::MAX outputs"),
                        };

                        let index = dbtx
                            .find_by_prefix_sorted_descending(&OutputPrefix)
                            .await
                            .next()
                            .await
                            .map_or(0, |entry| entry.0.0 + 1);

                        dbtx.insert_new_entry(&OutputKey(index), &Output(outpoint, tx_out.clone()))
                            .await;

                        debug!(
                            target: LOG_MODULE_WALLETV2,
                            output_index = index,
                            %outpoint,
                            value_sat = tx_out.value.to_sat(),
                            height,
                            "Recorded potential walletv2 receive"
                        );

                        potential_receives_num += 1;
                    }
                }
            }

            debug!(
                target: LOG_MODULE_WALLETV2,
                height,
                txs_num,
                potential_receives_num,
                "Scanned block"
            );
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

            if let Err(err) = self.btc_rpc.submit_transaction(unsigned.tx).await {
                debug!(
                    target: LOG_MODULE_WALLETV2,
                    err = %err.fmt_compact_anyhow(),
                    "Error broadcasting finalized transaction"
                );
            }
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
            .max(self.cfg.consensus.feerate_base << pending_txs.len());

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
            let code = self.descriptor(&utxo.tweak).ecdsa_sighash_script_code();

            let p2wsh_sighash = sighash_cache
                .p2wsh_signature_hash(index, &code, utxo.value, EcdsaSighashType::All)
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

    async fn get_outputs(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        start_index: u64,
        end_index: u64,
    ) -> Vec<OutputInfo> {
        let spent: BTreeSet<u64> = dbtx
            .find_by_range(SpentOutputKey(start_index)..SpentOutputKey(end_index))
            .await
            .map(|entry| entry.0.0)
            .collect()
            .await;

        dbtx.find_by_range(OutputKey(start_index)..OutputKey(end_index))
            .await
            .filter_map(|entry| {
                std::future::ready(entry.1.1.script_pubkey.is_p2wsh().then(|| OutputInfo {
                    index: entry.0.0,
                    script: entry.1.1.script_pubkey,
                    value: entry.1.1.value,
                    spent: spent.contains(&entry.0.0),
                    outpoint: Some(entry.1.0),
                }))
            })
            .collect()
            .await
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

    async fn tx_chain(&self, dbtx: &mut DatabaseTransaction<'_>) -> Vec<TxInfo> {
        dbtx.find_by_prefix(&TxInfoPrefix)
            .await
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
    pub async fn tx_chain_ui(&self) -> Vec<TxInfo> {
        self.tx_chain(&mut self.db.begin_transaction_nc().await)
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

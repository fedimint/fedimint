//! The pending receive scanner: a guardian-local, non-consensus view of the
//! receive outputs in its mempool and in the blocks just below its chain tip,
//! served to clients so they can render peg-in progress.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::Context;
use bitcoin::hashes::sha256;
use bitcoin::{Transaction, Txid};
use fedimint_core::envs::{is_env_var_set, is_running_in_test_env};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::FmtCompact as _;
use fedimint_logging::LOG_MODULE_WALLETV2;
use fedimint_server_core::bitcoin_rpc::ServerBitcoinRpcMonitor;
use fedimint_walletv2_common::{
    BLOCK_COUNT_VOTE_DELAY, MempoolVisibility, PendingOutput, PendingOutputs, is_potential_receive,
};
use tokio::sync::watch;
use tracing::debug;

use crate::envs::FM_WALLETV2_DISABLE_MEMPOOL_SCAN_ENV;

/// Number of blocks below the local chain tip that the pending receive scanner
/// reports on.
///
/// Only the first [`BLOCK_COUNT_VOTE_DELAY`] blocks of this window are
/// strictly necessary, since deeper outputs are already in the consensus output
/// log. The window deliberately extends past that so a peg-in keeps being
/// reported for a while after it becomes final: a client needs a moment to
/// notice the consensus entry and start its claim, and without the overlap its
/// progress display would briefly fall back to reporting nothing at all.
pub(crate) const MAX_PENDING_DEPTH: u64 = 2 * BLOCK_COUNT_VOTE_DELAY;

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

/// How long one pass may spend fetching mempool transactions before it
/// publishes what it has and starts the next pass.
///
/// Fetches are sequential, so a cold cache over a large mempool would otherwise
/// hold back the confirmations already gathered from the block scan until
/// every transaction had been fetched. Kept short under test so that a test can
/// observe a pass running out of budget without a large mempool.
fn mempool_scan_budget() -> Duration {
    if is_running_in_test_env!() {
        Duration::from_millis(100)
    } else {
        Duration::from_secs(5)
    }
}

/// How one pass over the guardian's mempool ended.
///
/// Clients only learn the resulting [`MempoolVisibility`]; the scanner also
/// needs to know *why* a pass stopped short, because a pass that ran out of
/// budget should continue right away while one that hit a failing backend
/// should wait before trying again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MempoolScan {
    /// The backend cannot enumerate a mempool, the scan is turned off, or
    /// listing the mempool failed.
    Unavailable,
    /// Fetching a transaction failed, so the pass gave up partway through.
    Failed,
    /// The pass spent its budget with transactions still left to fetch.
    OutOfBudget,
    /// Every transaction the backend listed is now in the cache.
    Complete,
}

impl MempoolScan {
    fn visibility(self) -> MempoolVisibility {
        match self {
            Self::Unavailable => MempoolVisibility::Unavailable,
            Self::Failed | Self::OutOfBudget => MempoolVisibility::Partial,
            Self::Complete => MempoolVisibility::Complete,
        }
    }
}

/// Collects the receive outputs of the transactions in the node's mempool.
///
/// A pass never fails outright, because the mempool is only ever the weakest
/// half of the pending view: losing it must not cost the mined half, which is
/// the stronger signal and is gathered from a backend that may well still be
/// working. Instead it reports how far it got.
///
/// A pass stops fetching once `budget` has elapsed, after fetching at least one
/// transaction so that every pass makes progress.
///
/// Only transactions absent from `cache` are fetched, and entries that have
/// left the mempool are dropped, so eviction and replacement are handled by
/// rebuilding the retained set rather than by tracking them explicitly. A
/// transaction that disappears between being listed and being fetched is
/// skipped rather than treated as an error, since that is the ordinary outcome
/// of it being mined mid-scan.
///
/// `cache` is never emptied on failure. Refilling it costs one fetch per
/// mempool transaction, so discarding it because a single call failed would
/// turn a transient error into repeated bursts of RPC work; whether its
/// contents may be *reported* is what the returned [`MempoolScan`] decides. A
/// pass that stops short still reports its cache: it was pruned against a fresh
/// listing, so every entry in it is real and the set is merely short of a few
/// transactions.
async fn scan_pending_mempool(
    btc_rpc: &ServerBitcoinRpcMonitor,
    pks_hash: &sha256::Hash,
    budget: Duration,
    cache: &mut MempoolCache,
) -> MempoolScan {
    let deadline = fedimint_core::time::now() + budget;

    let txids = match btc_rpc.get_mempool_txids().await {
        Ok(Some(txids)) => txids,
        // The backend has no mempool to enumerate, as esplora never does.
        Ok(None) => return MempoolScan::Unavailable,
        // Without a fresh listing the cache cannot be pruned, so it may hold
        // transactions that have since been mined or evicted. Report nothing
        // from it until a listing succeeds and prunes it again.
        Err(err) => {
            debug!(
                target: LOG_MODULE_WALLETV2,
                err = %err.fmt_compact(),
                "Error listing the mempool, reporting confirmations only"
            );

            return MempoolScan::Unavailable;
        }
    };

    let txids: BTreeSet<Txid> = txids.into_iter().collect();

    cache.retain(|txid, _| txids.contains(txid));

    let missing: Vec<Txid> = txids
        .into_iter()
        .filter(|txid| !cache.contains_key(txid))
        .collect();

    let mut missing = missing.into_iter().peekable();

    while let Some(txid) = missing.next() {
        match btc_rpc.get_mempool_tx(&txid).await {
            Ok(Some(tx)) => {
                cache.insert(txid, filtered_receive_outputs(&tx, pks_hash, None));
            }
            // The transaction left the mempool between being listed and being
            // fetched, so its absence from the cache is correct.
            Ok(None) => {}
            // A node that has the transaction but declines to return it answers
            // with code `-5`, which the backend already reports as `Ok(None)`,
            // so an error here is the backend itself failing and every
            // remaining fetch would fail the same way. Abandon the pass rather
            // than walk the rest of the mempool collecting the same error, and
            // report what was gathered: everything fetched so far stays cached,
            // so the next pass resumes from here instead of starting over.
            Err(err) => {
                debug!(
                    target: LOG_MODULE_WALLETV2,
                    %txid,
                    err = %err.fmt_compact(),
                    "Error fetching a mempool transaction, reporting a partial mempool"
                );

                return MempoolScan::Failed;
            }
        }

        // Checked after a fetch rather than before, so that even a budget
        // shorter than a single fetch makes progress on every pass.
        if missing.peek().is_some() && fedimint_core::time::now() >= deadline {
            return MempoolScan::OutOfBudget;
        }
    }

    MempoolScan::Complete
}

/// Collects every receive output a guardian can see but the federation has not
/// yet recorded, from the recent blocks and, unless `mempool_budget` is `None`
/// because the mempool scan is turned off, the mempool.
///
/// Also returns how the mempool pass ended, so the caller can tell whether to
/// continue straight away.
async fn scan_pending_receives(
    btc_rpc: &ServerBitcoinRpcMonitor,
    pks_hash: &sha256::Hash,
    mempool_budget: Option<Duration>,
    cache: &mut PendingCache,
) -> anyhow::Result<(PendingOutputs, MempoolScan)> {
    let status = btc_rpc
        .status()
        .context("Bitcoin backend is not connected")?;

    scan_pending_blocks(btc_rpc, pks_hash, status.block_count, &mut cache.blocks).await?;

    // The mempool pass never fails the whole scan. Propagating would discard
    // the mined progress gathered above, which is both the stronger signal and
    // still available: with an esplora fallback the block scan can succeed
    // while the mempool read, which only bitcoind can serve, does not.
    let mempool = match mempool_budget {
        Some(budget) => scan_pending_mempool(btc_rpc, pks_hash, budget, &mut cache.mempool).await,
        None => MempoolScan::Unavailable,
    };

    let mined = cache
        .blocks
        .values()
        .flat_map(|(_, outputs)| outputs.iter().cloned());

    // The cache survives a pass that could not report from it, so that a
    // transient failure does not force a refetch of the whole mempool next
    // time; what is reported is decided here instead of by emptying it.
    let unmined = (mempool != MempoolScan::Unavailable)
        .then(|| cache.mempool.values().flatten().cloned())
        .into_iter()
        .flatten();

    // A transaction mined between the two scans appears in both; the mined
    // entry is the stronger signal, so it wins on the client side by way of the
    // per-outpoint merge preferring a known height.
    let outputs = mined.chain(unmined).collect::<Vec<PendingOutput>>();

    debug!(
        target: LOG_MODULE_WALLETV2,
        block_count = status.block_count,
        ?mempool,
        mempool_txs_num = cache.mempool.len(),
        pending_outputs_num = outputs.len(),
        "Scanned for pending receives"
    );

    let pending = PendingOutputs {
        block_count: status.block_count,
        outputs,
        mempool_visibility: mempool.visibility(),
    };

    Ok((pending, mempool))
}

/// Maintains [`crate::Wallet::pending_outputs`] by scanning both the blocks
/// just below the guardian's local chain tip and its mempool.
///
/// This deliberately runs outside of consensus. Most of this window sits
/// above the consensus block count precisely because the federation does
/// not consider those blocks final yet, and each guardian sees a slightly
/// different tip, so nothing derived here may ever influence consensus
/// state. It exists only so clients can render peg-in progress rather than
/// showing nothing for the hour it takes a deposit to become claimable.
pub(crate) fn spawn_pending_receive_scanner(
    btc_rpc: ServerBitcoinRpcMonitor,
    pks_hash: sha256::Hash,
    sender: watch::Sender<PendingOutputs>,
    task_group: &TaskGroup,
) {
    // Read once rather than per scan: it selects how this guardian behaves
    // for its whole run, and a guardian that has opted out should not be
    // paying an env lookup on every chain tip either.
    let mempool_budget =
        (!is_env_var_set(FM_WALLETV2_DISABLE_MEMPOOL_SCAN_ENV)).then(mempool_scan_budget);

    task_group.spawn_cancellable("scan_pending_receives", async move {
        // Carried across scans so that each one only fetches blocks and
        // mempool transactions it has not already seen.
        let mut cache = PendingCache::default();

        // Follow the monitor's own refresh cadence rather than an
        // independent timer, so we never scan a chain tip that is already
        // stale by up to a full update interval.
        let mut status = btc_rpc.subscribe_status();

        loop {
            let scan = scan_pending_receives(&btc_rpc, &pks_hash, mempool_budget, &mut cache).await;

            let out_of_budget = match scan {
                Ok((pending, mempool)) => {
                    sender.send_replace(pending);

                    mempool == MempoolScan::OutOfBudget
                }
                Err(err) => {
                    // This view is advisory, so a guardian that cannot
                    // reach its bitcoin backend degrades to reporting
                    // nothing pending rather than failing.
                    debug!(
                        target: LOG_MODULE_WALLETV2,
                        err = %err.fmt_compact(),
                        "Error scanning for pending receives"
                    );

                    sender.send_replace(PendingOutputs::default());

                    false
                }
            };

            // A pass that ran out of budget has published what it gathered
            // and still has mempool transactions left to fetch, so carry on
            // now rather than a full monitor interval later. Every such
            // pass fetches at least one transaction, so this terminates
            // once the cache has caught up with the mempool.
            //
            // Yield first: the bitcoind backend's RPC futures run
            // synchronously via `block_in_place` and never return `Pending`,
            // so without this a catch-up would run every slice inside a
            // single poll and the enclosing `cancel_on_shutdown` could not
            // observe shutdown in between.
            if out_of_budget {
                tokio::task::yield_now().await;
                continue;
            }

            if status.changed().await.is_err() {
                break;
            }
        }
    });
}
